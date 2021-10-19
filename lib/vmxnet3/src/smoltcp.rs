// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

use alloc::boxed::Box;
use core::alloc::Layout;
use core::pin::Pin;

use driverkit::iomem::{IOBuf, IOBufChain, IOBufPool};
use driverkit::{devq::DevQueue, iomem::IOMemError};

use smoltcp::phy::{self, Device, DeviceCapabilities};
use smoltcp::time::Instant;
use smoltcp::Result;

use crate::vmx::VMXNet3;

/// define the maximum packet size supported
const MAX_PACKET_SZ: usize = 2048;

/// a smoltcp phy implementation wrapping a DevQueue
pub struct DevQueuePhy {
    device: Pin<Box<VMXNet3>>,
    pool_tx: IOBufPool,
    pool_rx: IOBufPool,
}

impl DevQueuePhy {
    pub fn new(device: Pin<Box<VMXNet3>>) -> core::result::Result<DevQueuePhy, IOMemError> {
        let pool_tx = IOBufPool::new(MAX_PACKET_SZ, MAX_PACKET_SZ)?;
        let pool_rx = IOBufPool::new(MAX_PACKET_SZ, MAX_PACKET_SZ)?;

        // Front-load an rx descriptor. This is necessary due to a bug in smoltcp
        // that requries there be at least one rx descriptor before data can be received.
        let mut chain = IOBufChain::new(0, 2).expect("Can't make IoBufChain?");
        let layout = Layout::from_size_align(MAX_PACKET_SZ, 128).expect("Correct Layout");

        let mut seg0 = IOBuf::new(layout).expect("Can't make packet?");
        seg0.expand();
        let mut seg1 = IOBuf::new(layout).expect("Can't make packet?");
        seg1.expand();

        chain.segments.push_back(seg0);
        chain.segments.push_back(seg1);

        let mut device = device;
        device.rxq[0].enqueue(chain).expect("Can enqueue RX desc");
        assert!(device.rxq[0].flush().is_ok());

        Ok(Self {
            device,
            pool_tx,
            pool_rx,
        })
    }
}

impl<'a> Device<'a> for DevQueuePhy {
    type RxToken = RxPacket<'a>;
    type TxToken = TxPacket<'a>;

    /// Obtains a receive buffer along a side a send buffer for replies (e.g., ping...)
    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        // check if there is any packet available in the receive queue
        let numdeq = self.device.rxq[0].can_dequeue(false);

        if numdeq > 0 {
            // Get a packet, for now just one
            let packet = self.device.rxq[0].dequeue().expect("numdeq was >0");
            assert!(self.device.rxq[0].flush().is_ok());

            // Enqueue another buffer for future receives
            // TODO: maybe we need to enqueue more than one?

            // info!("RX: new rx buffer chain");
            let layout = Layout::from_size_align(MAX_PACKET_SZ, 128).expect("Correct Layout");
            let mut bufs = IOBufChain::new(0, 2).expect("Can't make chain?");
            let seg0 = IOBuf::new(layout).expect("Can't make packet?");
            let seg1 = IOBuf::new(layout).expect("Can't make packet?");
            bufs.append(seg0);
            bufs.append(seg1);
            let enq = self.device.rxq[0].enqueue(bufs);
            assert!(enq.is_ok());

            // construct the RX token
            let rx_token = RxPacket::new(packet, &mut self.pool_rx);

            // get an empty TX token from the pool...
            // TODO: make sure we can actually send something!
            let numdeq = self.device.txq[0].can_dequeue(false);
            let iobuf = if numdeq > 0 {
                // info!("TX: reusing buffer chain");
                self.device.txq[0].dequeue().expect("Couldn't dequeue?")
            } else {
                // info!("TX: new buffer chain");
                let mut iobuf = IOBufChain::new(0, 1).expect("Can't create chain?");
                let layout = Layout::from_size_align(MAX_PACKET_SZ, 128).expect("Correct Layout");
                let seg0 = IOBuf::new(layout).expect("Can't make packet?");

                iobuf.append(seg0);
                iobuf
            };

            // let iobuf = self.get_tx_iobuf_chain();
            // let mut iobuf = IOBufChain::new(0, 1).expect("Can't make chain?");
            // let buf2 = self.pool_tx.get_buf().expect("Can't get buffer?");
            // iobuf.append(buf2);
            let tx_token = TxPacket::new(iobuf, &mut self.device.txq[0], &mut self.pool_tx);

            Some((rx_token, tx_token))
        } else {
            // info!("Nothing to receive!");
            assert!(self.device.rxq[0].flush().is_ok());
            None
        }
    }

    /// Obtains/allocates an empty end buffer
    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        // see if there is something to dequeue
        let numdeq = self.device.txq[0].can_dequeue(false);

        let packet = if numdeq > 0 {
            // info!("TX: reusing buffer chain");
            self.device.txq[0].dequeue().expect("Couldn't dequeue?")
        } else {
            // info!("TX: new buffer chain");
            let mut iobuf = IOBufChain::new(0, 1).expect("Can't create chain?");
            iobuf.append(self.pool_tx.get_buf().expect("Can't get buffer from pool"));
            iobuf
        };

        // get an empty TX token from the pool
        Some(TxPacket::new(
            packet,
            &mut self.device.txq[0],
            &mut self.pool_tx,
        ))
    }

    /**
     * the device capabilities (e.g., checksum offloading etc...)
     */
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(1);
        caps
    }
}

/// smolnet RxToken

/// smolnet TxToken
pub struct RxPacket<'a> {
    iobuf: IOBufChain,
    pool: &'a mut IOBufPool,
}

impl<'a> RxPacket<'a> {
    fn new(iobuf: IOBufChain, pool: &'a mut IOBufPool) -> RxPacket<'a> {
        RxPacket { iobuf, pool }
    }
}

impl<'a> phy::RxToken for RxPacket<'a> {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        // XXX: not sure here if the buffer actually needs to be copied here...
        let result = f(&mut self.iobuf.segments[0].as_mut_slice());
        // info!("RxToken::consume n segments:{}", self.iobuf.segments.len());

        // we can drop the IOBufChain here.
        for s in self.iobuf.segments {
            self.pool.put_buf(s);
        }

        result
    }
}

/// smolnet TxToken
pub struct TxPacket<'a> {
    iobuf: Option<IOBufChain>,
    txq: &'a mut dyn DevQueue,
    pool: &'a mut IOBufPool,
}

impl<'a> TxPacket<'a> {
    fn new(iobuf: IOBufChain, txq: &'a mut dyn DevQueue, pool: &'a mut IOBufPool) -> TxPacket<'a> {
        TxPacket {
            iobuf: Some(iobuf),
            txq,
            pool,
        }
    }
}

/// implements the TxToken trait for the TxPacket
impl<'a> phy::TxToken for TxPacket<'a> {
    fn consume<R, F>(mut self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        // info!("TxToken::consume");
        let mut iobuf = self.iobuf.take().unwrap();

        // let the network stack write into the packet
        iobuf.segments[0].expand();
        iobuf.segments[0].truncate(len);
        let result = f(&mut iobuf.segments[0].as_mut_slice());

        // TODO: send packet out, this passes ownership of the IOBufChain to the device
        // XXX: can we guarantee that there is space in the queue?
        assert!(self.txq.enqueue(iobuf).is_ok());
        assert!(self.txq.flush().is_ok());

        // references dropped...
        result
    }
}

/// Drop trait to return a dropped Tx token back to the pool
impl<'a> Drop for TxPacket<'a> {
    /// gets called when the TxPacket gets dropped in the stack
    fn drop(&mut self) {
        // info!("drop the TxPacket reference has buf: {}", !self.iobuf.is_none());
        // TODO: return the buffer back to the pool.
        if !self.iobuf.is_none() {
            let iobuf = self.iobuf.take().unwrap();
            // info!("TxToken::consume n segments:{}", iobuf.segments.len());
            // we can drop the IOBufChain here.
            for s in iobuf.segments {
                self.pool.put_buf(s);
            }
        }
    }
}
