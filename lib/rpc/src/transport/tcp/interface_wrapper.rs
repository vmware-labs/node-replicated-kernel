// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use smoltcp::iface::{Context, Interface, SocketHandle};
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
const MAX_CHANNELS: usize = MAX_INFLIGHT_MSGS;

struct InterfaceState<'a, D: for<'d> Device<'d>> {
    iface: Interface<'a, D>,
    handles: ArrayVec<SocketHandle, MAX_SOCKETS>,
}

struct SocketTask {
    offset: usize,
    buf: Arc<[u8]>,
}

struct MultichannelSocket {
    /* general state */
    num_channels: Arc<Mutex<usize>>,
    connect_data: Arc<Mutex<Option<((IpAddress, u16), u16)>>>,

    /* send state */
    /// What channel to check for send in next. Useful for in-progress sends,
    /// but also for round-robin sending across channels in make_progress()
    send_channel: Arc<Mutex<usize>>,
    send_tasks: ArrayVec<Arc<Mutex<Option<SocketTask>>>, MAX_CHANNELS>,
    send_doorbells: ArrayVec<AtomicBool, MAX_CHANNELS>,

    /* recv state */
    recv_in_progress: Arc<Mutex<Option<(usize, usize)>>>, // (channel, data_remaining)
    any_recv: Arc<Mutex<Option<usize>>>,
    recv_tasks: ArrayVec<Arc<Mutex<Option<SocketTask>>>, MAX_CHANNELS>,
    recv_doorbells: ArrayVec<AtomicBool, MAX_CHANNELS>,
    finished_recvs: ArrayVec<Arc<Mutex<Option<Arc<[u8]>>>>, MAX_CHANNELS>,
}

impl MultichannelSocket {
    fn new() -> MultichannelSocket {
        let mut send_tasks = ArrayVec::new();
        let mut send_doorbells = ArrayVec::new();

        let mut recv_tasks = ArrayVec::new();
        let mut recv_doorbells = ArrayVec::new();
        let mut finished_recvs = ArrayVec::new();

        for _ in 0..MAX_CHANNELS {
            send_tasks.push(Arc::new(Mutex::new(None)));
            send_doorbells.push(AtomicBool::new(false));

            recv_tasks.push(Arc::new(Mutex::new(None)));
            recv_doorbells.push(AtomicBool::new(false));
            finished_recvs.push(Arc::new(Mutex::new(None)));
        }

        MultichannelSocket {
            num_channels: Arc::new(Mutex::new(0)),
            connect_data: Arc::new(Mutex::new(None)),

            send_channel: Arc::new(Mutex::new(0)),
            send_tasks,
            send_doorbells,

            any_recv: Arc::new(Mutex::new(None)),
            recv_in_progress: Arc::new(Mutex::new(None)),
            recv_tasks,
            recv_doorbells,
            finished_recvs,
        }
    }

    fn connect(&self, cx: &mut Context, socket: &mut TcpSocket) {
        // TODO: add timeout?? with error returned if timeout occurs?
        if let Some((addr, local_port)) = *self.connect_data.lock() {
            if let Err(e) = socket.connect(cx, addr, local_port) {
                log::error!("Failed to connect client socket: {:?}", e);
                //return Err(RPCError::TransportError);
            }
        }
    }

    fn send(&self, socket: &mut TcpSocket) {
        let num_channels = *self.num_channels.lock();
        let mut start_channel_id = self.send_channel.lock();
        let mut current_channel_id = *start_channel_id;

        while socket.can_send() {
            let mut send_task_opt = self.send_tasks[current_channel_id].lock(); // TODO: make this a try-lock
            if let Some(ref mut task) = *send_task_opt {
                // Attempt to send until end of data array
                if let Ok(bytes_sent) = socket.send_slice(&(task.buf[task.offset..])) {
                    log::debug!("sent [{:?}-{:?}]", task.offset, task.offset + bytes_sent);
                    task.offset += bytes_sent;

                    if task.offset == task.buf.len() {
                        // We finished sending the send buf, so let it go
                        *send_task_opt = None;
                        self.send_doorbells[current_channel_id].store(true, Ordering::SeqCst);
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

    fn recv(&self, socket: &mut TcpSocket) {
        let num_channels = *self.num_channels.lock();
        let mut any_recv = self.any_recv.lock();
        let mut in_progress = self.recv_in_progress.lock();
        while socket.may_recv() {
            let (channel_id, mut data_remaining) = if let Some((channel_id, data_remaining)) =
                *in_progress
            {
                // We know what to do if there's a message partially received
                (channel_id, data_remaining)
            } else {
                // If a message is not partially received, we need to choose the channel to receive from
                // Let's first seek if we can peek a message header.
                if let Ok(hdr_ptr) = socket.peek(HDR_LEN) {
                    if hdr_ptr.len() == HDR_LEN {
                        let hdr = RPCHeader::from_bytes(hdr_ptr);
                        log::trace!("Peeked header msg_id={:?}", hdr);

                        let channel = if let Some(channel_id) = *any_recv {
                            // If any recv, choose the next channel based on index, first to have recv buffer
                            // If no buffer available, break.
                            let mut recv_channel = None;
                            for channel_offset in 0..num_channels {
                                let current_channel = (channel_id + channel_offset) % num_channels;
                                if (*self.recv_tasks[current_channel].lock()).is_some() {
                                    recv_channel = Some(current_channel);
                                    break;
                                }
                            }
                            if let Some(available_recv_channel) = recv_channel {
                                available_recv_channel
                            } else {
                                break;
                            }
                        } else {
                            hdr.msg_id as usize
                        };
                        (channel, HDR_LEN + hdr.msg_len as usize)
                    } else {
                        break;
                    }
                } else {
                    // If we can't peek, there's not actually data we need to worry about.
                    break;
                }
            };

            let mut finished = false;
            let mut started = false;
            let mut recv_task_opt = self.recv_tasks[channel_id].lock(); // TODO: make this a try-lock
            if let Some(ref mut task) = *recv_task_opt {
                // Attempt to receive until end of data array
                let buf_len = task.buf.len();
                let recv_buf = Arc::get_mut(&mut task.buf).unwrap();

                // Check to see if receive buffer has enough space to receive the messsage
                if buf_len - task.offset < data_remaining {
                    panic!("Not enough room in receive buffer ({:?}) for incoming message with {:?} bytes to be received", 
                                buf_len, task.offset + data_remaining);
                }

                if let Ok(bytes_recv) =
                    socket.recv_slice(&mut recv_buf[task.offset..task.offset + data_remaining])
                {
                    if bytes_recv > 0 {
                        log::debug!("recv [{:?}-{:?}]", task.offset, task.offset + bytes_recv);

                        if !started {
                            started = true;
                        }

                        task.offset += bytes_recv;
                        data_remaining -= bytes_recv;
                        if data_remaining == 0 {
                            finished = true;
                        }
                    }
                }
            }

            if finished {
                // We finished receiving into the recv buf, so let it go
                let mut finished_opt = self.finished_recvs[channel_id].lock();
                let task = recv_task_opt.as_ref().unwrap();
                *finished_opt = Some(task.buf.clone());
                *recv_task_opt = None;
                self.recv_doorbells[channel_id].store(true, Ordering::SeqCst);

                // If any receive, aim to receive round-robin style.
                if let Some(channel_id) = *any_recv {
                    *any_recv = Some((channel_id + 1) % num_channels);
                }
            } else if started {
                // We started reading a message but didn't finish - we need to record progress.
                *in_progress = Some((channel_id, data_remaining));
            }
        }
    }
}

pub struct InterfaceWrapper<'a, D: for<'d> Device<'d>> {
    // This is data that is only used during socket setup or make progress.
    iface_state: Arc<Mutex<InterfaceState<'a, D>>>,

    sockets: ArrayVec<MultichannelSocket, MAX_SOCKETS>,
}

impl<'a, D: for<'d> Device<'d>> InterfaceWrapper<'a, D> {
    pub fn new(iface: Interface<'a, D>) -> InterfaceWrapper<'a, D> {
        lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);
        lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);

        let mut sockets = ArrayVec::new();
        for _ in 0..MAX_SOCKETS {
            sockets.push(MultichannelSocket::new());
        }

        InterfaceWrapper {
            iface_state: Arc::new(Mutex::new(InterfaceState {
                iface,
                handles: ArrayVec::new(),
            })),
            sockets,
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
                {
                    let mut connect_data = self.sockets[id].connect_data.lock();
                    *connect_data = Some((addr, local_port));
                }

                // If the socket is a connecting socket, connect
                let (tcpsocket, cx) = state.iface.get_socket_and_context::<TcpSocket>(handle);
                self.sockets[id].connect(cx, tcpsocket);
            }

            // Do this why we hold the iface_state lock, so that no one tries to make progress
            // on this socket before it's initialized.
            let mut socket_channels = self.sockets[id].num_channels.lock();
            *socket_channels = num_channels;
            if server_addr.is_none() {
                let mut any_recv = self.sockets[id].any_recv.lock();
                *any_recv = Some(0);
            }
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
        log::trace!("make_progress()");

        match state.iface.poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }

        // Try to make some progress
        for socket_id in 0..state.handles.len() {
            let handle = state.handles[socket_id];
            let mut tcpsocket = state.iface.get_socket::<TcpSocket>(handle);
            let multisocket = &self.sockets[socket_id];

            if tcpsocket.is_open() {
                // If this socket can send, send any outgoing data.
                multisocket.send(&mut tcpsocket);
                // If this socket can recv, recv any incoming data.
                multisocket.recv(&mut tcpsocket);
            } else {
                let (tcpsocket, cx) = state.iface.get_socket_and_context::<TcpSocket>(handle);
                multisocket.connect(cx, tcpsocket);
            }
        }
    }

    // TODO: msg_id must be equal to the header msg_id
    pub fn send_msg(
        &self,
        socket_id: SocketId,
        msg_id: MsgId,
        send_buf: Arc<[u8]>,
    ) -> Result<(), RPCError> {
        let channel_id = msg_id as usize;
        let socket = &self.sockets[socket_id];
        {
            let mut send_task_option = socket.send_tasks[channel_id].lock();
            *send_task_option = Some(SocketTask {
                offset: 0,
                buf: send_buf,
            });
        }
        self.wait_for_doorbell(&socket.send_doorbells[channel_id])?;
        Ok(())
    }

    pub fn recv_msg(
        &self,
        socket_id: SocketId,
        msg_id: MsgId,
        recv_buf: Arc<[u8]>,
    ) -> Result<Arc<[u8]>, RPCError> {
        let channel_id = msg_id as usize;
        let socket = &self.sockets[socket_id];
        {
            let mut recv_task_option = socket.recv_tasks[channel_id].lock();
            *recv_task_option = Some(SocketTask {
                offset: 0,
                buf: recv_buf,
            });
        }

        self.wait_for_doorbell(&socket.recv_doorbells[channel_id])?;
        let mut populated_finished_recv = socket.finished_recvs[channel_id].lock();

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
    use alloc::sync::Arc;
    use core::mem::MaybeUninit;
    use std::thread;

    use smoltcp::wire::IpAddress;
    use spin::Mutex;

    use crate::rpc::{RPCHeader, HDR_LEN};
    use crate::test::setup_test_logging;
    use crate::transport::tcp::interface_wrapper::InterfaceWrapper;
    use crate::transport::tcp::test::get_loopback_interface;

    #[test]
    fn test_instantiation() {
        setup_test_logging();

        let iface = get_loopback_interface();
        let _interface_wrapper = InterfaceWrapper::new(iface);
    }

    #[test]
    fn test_add_server_socket() {
        setup_test_logging();

        let iface = get_loopback_interface();
        let interface_wrapper = InterfaceWrapper::new(iface);
        interface_wrapper
            .add_socket(None, 10111, 1)
            .expect("Failed to add server socket");
    }

    #[test]
    fn test_add_client_socket() {
        setup_test_logging();

        let iface = get_loopback_interface();
        let interface_wrapper = InterfaceWrapper::new(iface);
        interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 1)
            .expect("Failed to add client socket");
    }

    #[test]
    fn test_add_socket_multi() {
        setup_test_logging();

        let iface = get_loopback_interface();

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
        setup_test_logging();

        let iface = get_loopback_interface();

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
            .send_msg(client_id, 0, buffer)
            .expect("Failed to send.");
    }

    #[test]
    fn test_send_multichannel() {
        setup_test_logging();

        let iface = get_loopback_interface();

        let num_send_channels = 3u8;
        let interface_wrapper = InterfaceWrapper::new(iface);
        let client_id = interface_wrapper
            .add_socket(
                Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                10111,
                num_send_channels as usize,
            )
            .expect("Failed to add client socket");
        let _server_id = interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");

        let send_data = [0u8; 10];
        for i in 0..num_send_channels {
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
                .send_msg(client_id, i, buffer)
                .expect("Failed to send.");
        }
    }

    #[test]
    fn test_send_multichannel_concurrent() {
        setup_test_logging();

        let iface = get_loopback_interface();

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
                    .send_msg(client_id, i, buffer)
                    .expect("Failed to send.");
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_recv() {
        setup_test_logging();

        let iface = get_loopback_interface();

        let interface_wrapper = InterfaceWrapper::new(iface);
        let client_id = interface_wrapper
            .add_socket(Some((IpAddress::v4(127, 0, 0, 1), 10110)), 10111, 1)
            .expect("Failed to add client socket");
        let server_id = interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");

        let hdr = RPCHeader {
            msg_id: 0,
            msg_type: 10,
            msg_len: 6,
        };
        let hdr_bytes = unsafe { hdr.as_bytes() };
        let mut send_data = [3u8; 10];
        for i in 0..HDR_LEN {
            send_data[i] = hdr_bytes[i];
        }
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
            .send_msg(client_id, 0, send_buffer)
            .expect("Failed to send.");

        let response = {
            let recv_buffer = Arc::<[u8]>::new_uninit_slice(10);
            let recv_buffer = unsafe {
                // Safety:
                // - It's not initialized, but recv will initialize it. This is not ideal, but it works.
                recv_buffer.assume_init()
            };

            interface_wrapper
                .recv_msg(server_id, 0, recv_buffer)
                .expect("Failed to receive")
        };
        for i in HDR_LEN..10 {
            assert_eq!(response[i], 3);
        }
    }

    #[test]
    fn test_recv_anychannel() {
        setup_test_logging();

        let iface = get_loopback_interface();

        let num_send_channels = 3u8;

        let interface_wrapper = InterfaceWrapper::new(iface);
        let client_id = interface_wrapper
            .add_socket(
                Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                10111,
                num_send_channels as usize,
            )
            .expect("Failed to add client socket");
        let server_id = interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");

        for i in 0..num_send_channels {
            let hdr = RPCHeader {
                msg_id: i,
                msg_type: 10,
                msg_len: 6,
            };
            let hdr_bytes = unsafe { hdr.as_bytes() };
            let mut send_data = [3u8; 10];
            for i in 0..HDR_LEN {
                send_data[i] = hdr_bytes[i];
            }

            for j in HDR_LEN..send_data.len() {
                send_data[j] = i;
            }

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
                .send_msg(client_id, i, buffer)
                .expect("Failed to send.");
        }

        for i in 0..num_send_channels {
            let response = {
                let recv_buffer = Arc::<[u8]>::new_uninit_slice(10);
                let recv_buffer = unsafe {
                    // Safety:
                    // - It's not initialized, but recv will initialize it. This is not ideal, but it works.
                    recv_buffer.assume_init()
                };

                interface_wrapper
                    .recv_msg(server_id, 0, recv_buffer)
                    .expect("Failed to receive")
            };
            for j in HDR_LEN..10 {
                assert_eq!(response[j], i);
            }
        }
    }

    #[test]
    fn test_recv_anychannel_concurrent() {
        setup_test_logging();

        let iface = get_loopback_interface();

        let num_client_channels = 5u8;

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
        let client_id = interface_wrapper
            .add_socket(
                Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                10111,
                num_client_channels as usize,
            )
            .expect("Failed to add client socket");
        let server_id = interface_wrapper
            .add_socket(None, 10110, 1)
            .expect("Failed to add server socket");

        let mut threads = Vec::new();
        for i in 0u8..num_client_channels {
            let my_interface_wrapper = interface_wrapper.clone();
            threads.push(thread::spawn(move || {
                // Setup for send
                let hdr = RPCHeader {
                    msg_id: i,
                    msg_type: 10,
                    msg_len: 6,
                };
                let hdr_bytes = unsafe { hdr.as_bytes() };
                let mut send_data = [3u8; 10];
                for j in 0..HDR_LEN {
                    send_data[j] = hdr_bytes[j];
                }
                for j in HDR_LEN..send_data.len() {
                    send_data[j] = i;
                }
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
                    .send_msg(client_id, i, buffer)
                    .expect("Failed to send.");
            }));
        }

        for _i in 0u8..num_client_channels {
            let response = {
                let recv_buffer = Arc::<[u8]>::new_uninit_slice(10);
                let recv_buffer = unsafe {
                    // Safety:
                    // - It's not initialized, but recv will initialize it. This is not ideal, but it works.
                    recv_buffer.assume_init()
                };

                interface_wrapper
                    .recv_msg(server_id, 0, recv_buffer)
                    .expect("Failed to receive")
            };
            let hdr = RPCHeader::from_bytes(&response[0..HDR_LEN]);
            for j in HDR_LEN..10 {
                assert_eq!(response[j], hdr.msg_id);
            }
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_recv_multi_concurrent() {
        setup_test_logging();

        let iface = get_loopback_interface();

        let num_channels = 5u8;

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
        let client_id = interface_wrapper
            .add_socket(
                Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                10111,
                num_channels as usize,
            )
            .expect("Failed to add client socket");
        let server_id = interface_wrapper
            .add_socket(None, 10110, num_channels as usize)
            .expect("Failed to add server socket");

        let mut threads = Vec::new();
        for i in 0u8..num_channels {
            let my_interface_wrapper = interface_wrapper.clone();
            threads.push(thread::spawn(move || {
                // Setup for send
                let hdr = RPCHeader {
                    msg_id: i,
                    msg_type: 10,
                    msg_len: 6,
                };
                let hdr_bytes = unsafe { hdr.as_bytes() };
                let mut send_data = [3u8; 10];
                for j in 0..HDR_LEN {
                    send_data[j] = hdr_bytes[j];
                }
                for j in HDR_LEN..send_data.len() {
                    send_data[j] = i;
                }
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
                    .send_msg(client_id, i, buffer)
                    .expect("Failed to send.");
            }));
        }

        let receiving = Arc::new(Mutex::new(0));

        for i in 0u8..num_channels {
            let my_interface_wrapper = interface_wrapper.clone();
            let my_receiving = receiving.clone();
            threads.push(thread::spawn(move || {
                loop {
                    {
                        let mut local_receiving = my_receiving.lock();
                        if *local_receiving < num_channels {
                            *local_receiving += 1;
                        } else {
                            break;
                        }
                    }

                    let response = {
                        let recv_buffer = Arc::<[u8]>::new_uninit_slice(10);
                        let recv_buffer = unsafe {
                            // Safety:
                            // - It's not initialized, but recv will initialize it. This is not ideal, but it works.
                            recv_buffer.assume_init()
                        };

                        my_interface_wrapper
                            .recv_msg(server_id, i, recv_buffer)
                            .expect("Failed to receive")
                    };
                    let hdr = RPCHeader::from_bytes(&response[0..HDR_LEN]);
                    for j in HDR_LEN..10 {
                        assert_eq!(response[j], hdr.msg_id);
                    }
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_recv_multisocket_multichannel_concurrent() {
        setup_test_logging();

        let num_sockets = 3u8;
        let num_channels = 3u8;

        let iface = get_loopback_interface();

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));

        let mut threads = Vec::new();
        for socket in 0u8..num_sockets {
            let client_id = interface_wrapper
                .add_socket(
                    Some((IpAddress::v4(127, 0, 0, 1), 10110 + socket as u16)),
                    10110 + num_sockets as u16 + socket as u16,
                    num_channels as usize,
                )
                .expect("Failed to add client socket");
            for i in 0u8..num_channels {
                let my_interface_wrapper = interface_wrapper.clone();
                threads.push(thread::spawn(move || {
                    // Setup for send
                    let hdr = RPCHeader {
                        msg_id: i,
                        msg_type: 10,
                        msg_len: 6,
                    };
                    let hdr_bytes = unsafe { hdr.as_bytes() };
                    let mut send_data = [3u8; 10];
                    for j in 0..HDR_LEN {
                        send_data[j] = hdr_bytes[j];
                    }
                    for j in HDR_LEN..send_data.len() {
                        send_data[j] = i;
                    }
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
                        .send_msg(client_id, i, buffer)
                        .expect("Failed to send.");
                }));
            }
        }

        for socket in 0u8..num_sockets {
            let server_id = interface_wrapper
                .add_socket(None, 10110 + socket as u16, num_channels as usize)
                .expect("Failed to add server socket");

            let receiving = Arc::new(Mutex::new(0));
            for i in 0u8..num_channels {
                let my_interface_wrapper = interface_wrapper.clone();
                let my_receiving = receiving.clone();
                threads.push(thread::spawn(move || {
                    loop {
                        {
                            let mut local_receiving = my_receiving.lock();
                            if *local_receiving < num_channels {
                                *local_receiving += 1;
                            } else {
                                break;
                            }
                        }

                        let response = {
                            let recv_buffer = Arc::<[u8]>::new_uninit_slice(10);
                            let recv_buffer = unsafe {
                                // Safety:
                                // - It's not initialized, but recv will initialize it. This is not ideal, but it works.
                                recv_buffer.assume_init()
                            };

                            let ret = my_interface_wrapper
                                .recv_msg(server_id, i, recv_buffer)
                                .expect("Failed to receive");
                            ret
                        };
                        let hdr = RPCHeader::from_bytes(&response[0..HDR_LEN]);
                        for j in HDR_LEN..10 {
                            assert_eq!(response[j], hdr.msg_id);
                        }
                    }
                }));
            }
        }

        for t in threads {
            t.join().unwrap();
        }
    }
}
