use log::info;

use driverkit::iomem::{IOBufChain, IOBufPool};
use driverkit::{devq::DevQueue, iomem::IOMemError};

use smoltcp::phy::{self, Device, DeviceCapabilities};
use smoltcp::time::Instant;
use smoltcp::Result;

use crate::vmx::VMXNet3;

/// define the maximum packet size supported
const MAX_PACKET_SZ: usize = 2048;

/// a smoltcp phy implementation wrapping a DevQueue
pub struct DevQueuePhy {
    device: VMXNet3,
    pool: IOBufPool,
}

impl DevQueuePhy {
    pub fn new(device: VMXNet3) -> core::result::Result<DevQueuePhy, IOMemError> {
        let pool = IOBufPool::new(MAX_PACKET_SZ, MAX_PACKET_SZ)?;
        Ok(Self { device, pool })
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

            // Enqueue another buffer for future receives
            // TODO: maybe we need to enqueue more than one?
            let mut bufs = IOBufChain::new(0, 1).expect("Can't make chain?");
            bufs.append(self.pool.get_buf().expect("Can't get buffer?"));
            let buf2 = self.pool.get_buf().expect("Can't get buffer?");

            assert!(self.device.rxq[0].enqueue(bufs).is_ok());

            // construct the RX token
            let rx_token = RxPacket::new(packet, &mut self.pool);

            // get an empty TX token from the pool...
            // TODO: make sure we can actually send something!
            let mut iobuf = IOBufChain::new(0, 1).expect("Can't make chain?");
            iobuf.append(buf2);
            let tx_token = TxPacket::new(iobuf, &mut self.device.txq[0]);

            Some((rx_token, tx_token))
        } else {
            None
        }
    }

    /// Obtains/allocates an empty end buffer
    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        // see if there is something to dequeue
        let numdeq = self.device.txq[0].can_dequeue(false);

        let packet = if numdeq > 0 {
            self.device.txq[0].dequeue().expect("Couldn't dequeue?")
        } else {
            let mut iobuf = IOBufChain::new(0, 1).expect("Can't create chain?");
            iobuf.append(self.pool.get_buf().expect("Can't get buffer from pool"));
            iobuf
        };

        // get an empty TX token from the pool
        Some(TxPacket::new(packet, &mut self.device.txq[0]))
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
        info!("rx called");

        // we can drop the IOBufChain here.
        self.pool
            .put_buf(self.iobuf.segments.pop_front().expect("Needs a seg"));
        result
    }
}

/// smolnet TxToken
pub struct TxPacket<'a> {
    iobuf: Option<IOBufChain>,
    txq: &'a mut dyn DevQueue,
}

impl<'a> TxPacket<'a> {
    fn new(iobuf: IOBufChain, txq: &'a mut dyn DevQueue) -> TxPacket<'a> {
        TxPacket {
            iobuf: Some(iobuf),
            txq,
        }
    }
}

/// implements the TxToken trait for the TxPacket
impl<'a> phy::TxToken for TxPacket<'a> {
    fn consume<R, F>(mut self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        info!("tx called {}", len);
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
        // TODO: return the buffer back to the pool.
        // self.pool.put_buf(self.iobuf);
    }
}
