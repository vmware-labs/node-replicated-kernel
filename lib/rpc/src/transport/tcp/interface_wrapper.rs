// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::phy::Device;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;

use crate::rpc::*;

pub(crate) const RX_BUF_LEN: usize = 8192;
pub(crate) const TX_BUF_LEN: usize = 8192;

const MAX_SOCKETS: usize = 16;
pub(crate) type SocketId = usize;

pub struct InterfaceWrapper<'a, D: for<'d> Device<'d>> {
    // These could probably be bundled together
    // since both are only accessed in add_socket* and make_progress
    pub iface: Arc<Mutex<Interface<'a, D>>>,
    pub handles: Arc<Mutex<ArrayVec<SocketHandle, MAX_SOCKETS>>>,

    pub send_bufs: ArrayVec<Arc<Mutex<Option<(usize, Arc<[u8]>)>>>, MAX_SOCKETS>,
    pub send_doorbells: ArrayVec<AtomicBool, MAX_SOCKETS>,

    pub recv_bufs: ArrayVec<Arc<Mutex<Option<(usize, Arc<[u8]>)>>>, MAX_SOCKETS>,
    pub finished_recv_bufs: ArrayVec<Arc<Mutex<Option<Arc<[u8]>>>>, MAX_SOCKETS>,
    pub recv_doorbells: ArrayVec<AtomicBool, MAX_SOCKETS>,
}

impl<'a, D: for<'d> Device<'d>> InterfaceWrapper<'a, D> {
    pub fn new(iface: Interface<'a, D>) -> InterfaceWrapper<'a, D> {
        lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);
        lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);

        let mut send_bufs = ArrayVec::new();
        let mut send_doorbells = ArrayVec::new();
        let mut recv_bufs = ArrayVec::new();
        let mut finished_recv_bufs = ArrayVec::new();
        let mut recv_doorbells = ArrayVec::new();
        for _ in 0..MAX_SOCKETS {
            send_bufs.push(Arc::new(Mutex::new(None)));
            send_doorbells.push(AtomicBool::new(false));
            recv_bufs.push(Arc::new(Mutex::new(None)));
            finished_recv_bufs.push(Arc::new(Mutex::new(None)));
            recv_doorbells.push(AtomicBool::new(false));
        }

        InterfaceWrapper {
            iface: Arc::new(Mutex::new(iface)),

            handles: Arc::new(Mutex::new(ArrayVec::new())),

            send_bufs,
            send_doorbells,

            recv_bufs,
            finished_recv_bufs,
            recv_doorbells,
            //recv_hdr: Arc::new(Mutex::new(None)),
            //send_lock: AtomicBool::new(false),
        }
    }

    pub(crate) fn add_socket(
        &self,
        server_addr: Option<(IpAddress, u16)>,
        local_port: u16,
    ) -> Result<SocketId, RPCError> {
        // Create RX and TX buffers for the socket
        let mut sock_vec = Vec::new();
        sock_vec
            .try_reserve_exact(RX_BUF_LEN)
            .map_err(|_e| RPCError::MemoryAllocationError)?;
        sock_vec.resize(RX_BUF_LEN, 0);
        let socket_rx_buffer = TcpSocketBuffer::new(sock_vec);
        let mut sock_vec = Vec::new();
        sock_vec
            .try_reserve_exact(TX_BUF_LEN)
            .map_err(|_e| RPCError::MemoryAllocationError)?;
        sock_vec.resize(TX_BUF_LEN, 0);

        // Create the TCP socket
        let socket_tx_buffer = TcpSocketBuffer::new(sock_vec);
        let mut tcp_socket = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);

        if server_addr.is_none() {
            tcp_socket
                .listen(local_port)
                .map_err(|_| RPCError::ServerListenError)?;
        }

        // Add socket to interface and record socket handle
        let handle = self.iface.lock().add_socket(tcp_socket);

        // Add to servere handles
        let socket_id = {
            let mut handles = self.handles.lock();
            let id = handles.len();
            handles.push(handle);

            if let Some(addr) = server_addr {
                // Add socket to interface and record socket handle
                let mut iface = self.iface.lock();
                let (socket, cx) = iface.get_socket_and_context::<TcpSocket>(handle);

                // TODO: add timeout?? with error returned if timeout occurs?
                if let Err(e) = socket.connect(cx, addr, local_port) {
                    log::error!("Failed to connect client socket: {:?}", e);
                    return Err(RPCError::TransportError);
                }
            }
            id
        };
        Ok(socket_id)
    }

    fn wait_for_doorbell(&self, doorbell: &AtomicBool) -> Result<(), RPCError> {
        log::trace!("wait_for_doorbell()");
        loop {
            let try_iface = self.iface.try_lock();
            if doorbell
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
            if let Some(mut iface) = try_iface {
                self.make_progress(&mut *iface);
            }
        }
        Ok(())
    }

    fn make_progress(&self, iface: &mut Interface<'a, D>) {
        log::trace!("make_progress()");

        match iface.poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }

        // Try to make some progress
        let handles = self.handles.lock();
        for i in 0..handles.len() {
            let socket = iface.get_socket::<TcpSocket>(handles[i]);

            // If this socket can send, send any outgoing data.
            if socket.can_send() {
                let mut send_buf_opt = self.send_bufs[i].lock(); // TODO: make this a try-lock
                if let Some((mut offset, send_buf)) = &*send_buf_opt {
                    // Attempt to send until end of data array
                    if let Ok(bytes_sent) = socket.send_slice(&send_buf[offset..]) {
                        log::debug!(
                            "socket {:?} sent [{:?}-{:?}]",
                            i,
                            offset,
                            offset + bytes_sent
                        );
                        offset += bytes_sent;

                        if offset == send_buf.len() {
                            // We finished sending the send buf, so let it go
                            *send_buf_opt = None;
                            self.send_doorbells[i].store(true, Ordering::SeqCst);
                        }
                    }
                }
            }

            // If this socket can recv, recv any incoming data.
            if socket.may_recv() {
                let mut finished = false;
                let mut recv_buf_opt = self.recv_bufs[i].lock(); // TODO: make this a try-lock
                if let Some((mut offset, recv_buf_arc)) = &mut *recv_buf_opt {
                    // Attempt to receive until end of data array
                    let recv_buf = Arc::get_mut(recv_buf_arc).unwrap();
                    if let Ok(bytes_recv) = socket.recv_slice(&mut recv_buf[offset..]) {
                        if bytes_recv > 0 {
                            log::debug!(
                                "socket {:?} recv [{:?}-{:?}]",
                                i,
                                offset,
                                offset + bytes_recv
                            );

                            offset += bytes_recv;
                            if offset == recv_buf.len() {
                                finished = true;
                            }
                        }
                    }
                }

                if finished {
                    // We finished receiving into the recv buf, so let it go
                    let mut finished_opt = self.finished_recv_bufs[i].lock();
                    let (_, recv_buf_arc) = recv_buf_opt.as_ref().unwrap();
                    *finished_opt = Some(recv_buf_arc.clone());
                    *recv_buf_opt = None;
                    self.recv_doorbells[i].store(true, Ordering::SeqCst);
                }
            }
        }
    }

    pub fn send(&self, socket_id: SocketId, send_buf: Arc<[u8]>) -> Result<(), RPCError> {
        {
            let mut send_buf_option = self.send_bufs[socket_id].lock();
            *send_buf_option = Some((0, send_buf));
        }
        self.wait_for_doorbell(&self.send_doorbells[socket_id])?;
        Ok(())
    }

    pub fn recv(&self, socket_id: SocketId, recv_buf: Arc<[u8]>) -> Result<Arc<[u8]>, RPCError> {
        {
            let mut recv_buf_option = self.recv_bufs[socket_id].lock();
            *recv_buf_option = Some((0, recv_buf));
        }

        self.wait_for_doorbell(&self.recv_doorbells[socket_id])?;
        let mut populated_recv_buf = self.finished_recv_bufs[socket_id].lock();

        // Get a new reference
        let my_recv_buf = if let Some(buf) = &*populated_recv_buf {
            buf.clone()
        } else {
            panic!("There should be a receive buffer if the flag was set!");
        };

        // Drop old reference
        *populated_recv_buf = None;
        Ok(my_recv_buf)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::mem::MaybeUninit;
    use std::sync::Once;

    use smoltcp::iface::{InterfaceBuilder, NeighborCache};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

    use crate::transport::tcp::interface_wrapper::InterfaceWrapper;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(env_logger::init);
    }

    #[test]
    fn test_initialization() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 2] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let _interface_wrapper = InterfaceWrapper::new(iface);
    }

    #[test]
    fn test_add_server_socket() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 2] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let interface_wrapper = InterfaceWrapper::new(iface);
        interface_wrapper
            .add_socket(None, 10111)
            .expect("Failed to add server socket");
    }

    #[test]
    fn test_add_client_socket() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 2] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let interface_wrapper = InterfaceWrapper::new(iface);
        interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111)
            .expect("Failed to add client socket");
    }

    #[test]
    fn test_add_socket_multi() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 4] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let interface_wrapper = InterfaceWrapper::new(iface);
        interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111)
            .expect("Failed to add client socket");
        interface_wrapper
            .add_socket(None, 10110)
            .expect("Failed to add server socket");
        interface_wrapper
            .add_socket(None, 10112)
            .expect("Failed to add server socket");
        interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10112)), 10113)
            .expect("Failed to add client socket");
    }

    #[test]
    fn test_send() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 4] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let interface_wrapper = InterfaceWrapper::new(iface);
        let client_id = interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111)
            .expect("Failed to add client socket");
        let _server_id = interface_wrapper
            .add_socket(None, 10110)
            .expect("Failed to add server socket");

        let send_data = [0u8; 10];
        let mut buffer = Arc::<[u8]>::new_uninit_slice(send_data.len());
        let data = Arc::get_mut(&mut buffer).unwrap(); // not shared yet, no panic!
        MaybeUninit::write_slice(data, &send_data);

        let buffer = unsafe {
            // Safety:
            // - Length == send_data.len(): see above
            // - All initialized: plain-old-data, wrote all of slice, see above
            buffer.assume_init()
        };

        interface_wrapper
            .send(client_id, buffer)
            .expect("Failed to send.");
    }

    #[test]
    fn test_recv() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 4] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let interface_wrapper = InterfaceWrapper::new(iface);
        let client_id = interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111)
            .expect("Failed to add client socket");
        let server_id = interface_wrapper
            .add_socket(None, 10110)
            .expect("Failed to add server socket");

        let send_data = [3u8; 10];
        let mut send_buffer = Arc::<[u8]>::new_uninit_slice(send_data.len());
        let data = Arc::get_mut(&mut send_buffer).unwrap(); // not shared yet, no panic!
        MaybeUninit::write_slice(data, &send_data);

        let send_buffer = unsafe {
            // Safety:
            // - Length == send_data.len(): see above
            // - All initialized: plain-old-data, wrote all of slice, see above
            send_buffer.assume_init()
        };

        interface_wrapper
            .send(client_id, send_buffer)
            .expect("Failed to send.");

        let response = {
            let recv_buffer = Arc::<[u8]>::new_uninit_slice(10);
            let recv_buffer = unsafe {
                // Safety:
                // - It's not initialized, but recv will initialize it. This is not ideal, but it works.
                recv_buffer.assume_init()
            };

            interface_wrapper
                .recv(server_id, recv_buffer)
                .expect("Failed to receive")
        };
        for i in 0..10 {
            assert_eq!(response[i], 3);
        }
    }
}
