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

/// Max number of inflight-messages per socket
const MAX_CHANNELS: usize = MsgId::MAX as usize + 1;

struct InterfaceState<'a, D: for<'d> Device<'d>> {
    iface: Interface<'a, D>,
    handles: ArrayVec<SocketHandle, MAX_SOCKETS>,
}

struct SocketTask {
    offset: usize,
    buf: Arc<[u8]>,
}

struct SocketState {
    // TODO: this could be a read/write lock, as it's only written to once.
    num_channels: Arc<Mutex<usize>>,

    send_channel: Arc<Mutex<usize>>,

    send_tasks: ArrayVec<Arc<Mutex<Option<SocketTask>>>, MAX_CHANNELS>,
    send_doorbells: ArrayVec<AtomicBool, MAX_CHANNELS>,

    // TODO: support receive channels
    recv_task: Arc<Mutex<Option<SocketTask>>>,
    recv_doorbell: AtomicBool,
    finished_recv: Arc<Mutex<Option<Arc<[u8]>>>>,
}

impl SocketState {
    fn new() -> SocketState {
        let mut send_tasks = ArrayVec::new();
        let mut send_doorbells = ArrayVec::new();
        for _ in 0..MAX_CHANNELS {
            send_tasks.push(Arc::new(Mutex::new(None)));
            send_doorbells.push(AtomicBool::new(false));
        }

        SocketState {
            num_channels: Arc::new(Mutex::new(0)),
            send_channel: Arc::new(Mutex::new(0)),

            send_tasks,
            send_doorbells,

            recv_task: Arc::new(Mutex::new(None)),
            recv_doorbell: AtomicBool::new(false),
            finished_recv: Arc::new(Mutex::new(None)),
        }
    }
}

pub struct InterfaceWrapper<'a, D: for<'d> Device<'d>> {
    // This is data that is only used during socket setup or make progress.
    iface_state: Arc<Mutex<InterfaceState<'a, D>>>,

    socket_state: ArrayVec<SocketState, MAX_SOCKETS>,
}

impl<'a, D: for<'d> Device<'d>> InterfaceWrapper<'a, D> {
    pub fn new(iface: Interface<'a, D>) -> InterfaceWrapper<'a, D> {
        lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);
        lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);

        let mut socket_state = ArrayVec::new();
        for _ in 0..MAX_SOCKETS {
            socket_state.push(SocketState::new());
        }

        InterfaceWrapper {
            iface_state: Arc::new(Mutex::new(InterfaceState {
                iface,
                handles: ArrayVec::new(),
            })),
            socket_state,
        }
    }

    pub(crate) fn add_socket(
        &self,
        server_addr: Option<(IpAddress, u16)>,
        local_port: u16,
        num_channels: usize,
    ) -> Result<SocketId, RPCError> {
        assert!(num_channels > 0 && num_channels <= MAX_CHANNELS);

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

        // If the socket is a listening socket, listen
        if server_addr.is_none() {
            tcp_socket
                .listen(local_port)
                .map_err(|_| RPCError::ServerListenError)?;
        }

        // Add to servere handles
        let socket_id = {
            let mut state = self.iface_state.lock();

            // Add socket to interface and record socket handle
            let handle = state.iface.add_socket(tcp_socket);
            let id = state.handles.len();
            state.handles.push(handle);

            if let Some(addr) = server_addr {
                // If the socket is a connecting socket, connect
                let (socket, cx) = state.iface.get_socket_and_context::<TcpSocket>(handle);

                // TODO: add timeout?? with error returned if timeout occurs?
                if let Err(e) = socket.connect(cx, addr, local_port) {
                    log::error!("Failed to connect client socket: {:?}", e);
                    return Err(RPCError::TransportError);
                }
            }

            // Do this why we hold the iface_state lock, so that no one tries to make progress
            // on this socket before it's initialized.
            let mut socket_channels = self.socket_state[id].num_channels.lock();
            *socket_channels = num_channels;

            id
        };

        Ok(socket_id)
    }

    fn wait_for_doorbell(&self, doorbell: &AtomicBool) -> Result<(), RPCError> {
        log::trace!("wait_for_doorbell()");
        loop {
            let try_state = self.iface_state.try_lock();
            if doorbell
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
            if let Some(mut state) = try_state {
                self.make_progress(&mut *state);
            }
        }
        Ok(())
    }

    fn make_progress(&self, state: &mut InterfaceState<D>) {
        log::debug!("make_progress()");

        match state.iface.poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }

        // Try to make some progress
        for i in 0..state.handles.len() {
            let handle = state.handles[i];
            let socket = state.iface.get_socket::<TcpSocket>(handle);
            let socket_state = &self.socket_state[i];

            // If this socket can send, send any outgoing data.
            {
                let mut start_channel_id = socket_state.send_channel.lock();
                let num_channels = *socket_state.num_channels.lock();
                let mut current_channel_id = *start_channel_id;
                while socket.can_send() {
                    let mut send_task_opt = socket_state.send_tasks[current_channel_id].lock(); // TODO: make this a try-lock
                    if let Some(ref mut task) = *send_task_opt {
                        // Attempt to send until end of data array
                        if let Ok(bytes_sent) = socket.send_slice(&(task.buf[task.offset..])) {
                            log::debug!(
                                "socket {:?} sent [{:?}-{:?}]",
                                i,
                                task.offset,
                                task.offset + bytes_sent
                            );
                            task.offset += bytes_sent;

                            if task.offset == task.buf.len() {
                                // We finished sending the send buf, so let it go
                                *send_task_opt = None;
                                socket_state.send_doorbells[current_channel_id]
                                    .store(true, Ordering::SeqCst);
                                current_channel_id = (current_channel_id + 1) % num_channels;

                                // We've tried to send with all sockets, so we're done even if socket.can_send() is still true
                                if current_channel_id == *start_channel_id {
                                    break;
                                }
                            }
                        }
                    } else {
                        // If not work to do, move on to next channel.
                        current_channel_id = (current_channel_id + 1) % num_channels;

                        // We've tried to send with all sockets, so we're done even if socket.can_send() is still true
                        if current_channel_id == *start_channel_id {
                            break;
                        }
                    }
                }
                // Update the channel to start sending from next time.
                *start_channel_id = current_channel_id;
            }

            // If this socket can recv, recv any incoming data.
            if socket.may_recv() {
                let mut finished = false;
                let mut recv_task_opt = socket_state.recv_task.lock(); // TODO: make this a try-lock
                if let Some(ref mut task) = *recv_task_opt {
                    // Attempt to receive until end of data array
                    let recv_buf = Arc::get_mut(&mut task.buf).unwrap();
                    if let Ok(bytes_recv) = socket.recv_slice(&mut recv_buf[task.offset..]) {
                        if bytes_recv > 0 {
                            log::debug!(
                                "socket {:?} recv [{:?}-{:?}]",
                                i,
                                task.offset,
                                task.offset + bytes_recv
                            );

                            task.offset += bytes_recv;
                            if task.offset == recv_buf.len() {
                                finished = true;
                            }
                        }
                    }
                }

                if finished {
                    // We finished receiving into the recv buf, so let it go
                    let mut finished_opt = socket_state.finished_recv.lock();
                    let task = recv_task_opt.as_ref().unwrap();
                    *finished_opt = Some(task.buf.clone());
                    *recv_task_opt = None;
                    socket_state.recv_doorbell.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    pub fn send(
        &self,
        socket_id: SocketId,
        msg_id: MsgId,
        send_buf: Arc<[u8]>,
    ) -> Result<(), RPCError> {
        let channel_id = msg_id as usize;
        let socket_state = &self.socket_state[socket_id];
        {
            let mut send_task_option = socket_state.send_tasks[channel_id].lock();
            *send_task_option = Some(SocketTask {
                offset: 0,
                buf: send_buf,
            });
        }
        self.wait_for_doorbell(&socket_state.send_doorbells[channel_id])?;
        Ok(())
    }

    pub fn recv(&self, socket_id: SocketId, recv_buf: Arc<[u8]>) -> Result<Arc<[u8]>, RPCError> {
        let state = &self.socket_state[socket_id];
        {
            let mut recv_task_option = state.recv_task.lock();
            *recv_task_option = Some(SocketTask {
                offset: 0,
                buf: recv_buf,
            });
        }

        self.wait_for_doorbell(&state.recv_doorbell)?;
        let mut populated_finished_recv = state.finished_recv.lock();

        // Get a new reference
        let my_finished_recv = if let Some(buf) = &*populated_finished_recv {
            buf.clone()
        } else {
            panic!("There should be a receive buffer if the flag was set!");
        };

        // Drop old reference
        *populated_finished_recv = None;
        Ok(my_finished_recv)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use core::mem::MaybeUninit;
    use std::sync::Once;
    use std::thread;

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
            .add_socket(None, 10111, 1)
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
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 1)
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
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 1)
            .expect("Failed to add client socket");
        interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");
        interface_wrapper
            .add_socket(None, 10112, 1)
            .expect("Failed to add server socket");
        interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10112)), 10113, 1)
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
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 1)
            .expect("Failed to add client socket");
        let _server_id = interface_wrapper
            .add_socket(None, 10110, 1)
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
            .send(client_id, 0, buffer)
            .expect("Failed to send.");
    }

    #[test]
    fn test_send_multichannel() {
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
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 3)
            .expect("Failed to add client socket");
        let _server_id = interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");

        let send_data = [0u8; 10];
        let mut buffer0 = Arc::<[u8]>::new_uninit_slice(send_data.len());
        let data = Arc::get_mut(&mut buffer0).unwrap(); // not shared yet, no panic!
        MaybeUninit::write_slice(data, &send_data);

        let buffer0 = unsafe {
            // Safety:
            // - Length == send_data.len(): see above
            // - All initialized: plain-old-data, wrote all of slice, see above
            buffer0.assume_init()
        };

        let mut buffer1 = Arc::<[u8]>::new_uninit_slice(send_data.len());
        let data = Arc::get_mut(&mut buffer1).unwrap(); // not shared yet, no panic!
        MaybeUninit::write_slice(data, &send_data);

        let buffer1 = unsafe {
            // Safety:
            // - Length == send_data.len(): see above
            // - All initialized: plain-old-data, wrote all of slice, see above
            buffer1.assume_init()
        };

        let mut buffer2 = Arc::<[u8]>::new_uninit_slice(send_data.len());
        let data = Arc::get_mut(&mut buffer2).unwrap(); // not shared yet, no panic!
        MaybeUninit::write_slice(data, &send_data);

        let buffer2 = unsafe {
            // Safety:
            // - Length == send_data.len(): see above
            // - All initialized: plain-old-data, wrote all of slice, see above
            buffer2.assume_init()
        };

        interface_wrapper
            .send(client_id, 0, buffer0)
            .expect("Failed to send.");
        interface_wrapper
            .send(client_id, 1, buffer1)
            .expect("Failed to send.");
        interface_wrapper
            .send(client_id, 2, buffer2)
            .expect("Failed to send.");
    }

    #[test]
    fn test_send_multichannel_concurrent() {
        setup();

        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let num_client_channels = 5u8;

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
        let client_id = interface_wrapper
            .add_socket(
                Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                10111,
                num_client_channels as usize,
            )
            .expect("Failed to add client socket");
        let _server_id = interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");

        let mut threads = Vec::new();
        for i in 0u8..num_client_channels {
            let my_interface_wrapper = interface_wrapper.clone();
            threads.push(thread::spawn(move || {
                // Setup for send
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

                my_interface_wrapper
                    .send(client_id, i, buffer)
                    .expect("Failed to send.");
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
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
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 1)
            .expect("Failed to add client socket");
        let server_id = interface_wrapper
            .add_socket(None, 10110, 1)
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
            .send(client_id, 0, send_buffer)
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
