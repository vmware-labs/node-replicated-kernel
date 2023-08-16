// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use log::{debug, trace, warn};
use spin::Mutex;

use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::phy::Device;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;

use crate::rpc::*;
use crate::transport::Transport;

const RX_BUF_LEN: usize = 8192;
const TX_BUF_LEN: usize = 8192;

pub struct TCPTransport<'a, D: for<'d> Device<'d>> {
    iface: Arc<Mutex<Interface<'a, D>>>,
    server_handle: SocketHandle,
    server_ip: Option<IpAddress>,
    server_port: u16,
    client_port: u16,
    recv_hdr: Arc<Mutex<Option<RPCHeader>>>,
    send_lock: AtomicBool,
}

impl<'a, D: for<'d> Device<'d>> TCPTransport<'a, D> {
    pub fn new(
        server_ip: Option<IpAddress>,
        server_port: u16,
        client_port: u16,
        iface: Arc<Mutex<Interface<'a, D>>>,
    ) -> Result<TCPTransport<'a, D>, RPCError> {
        lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);
        lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);

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
        let tcp_socket = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);

        // Add socket to interface and record socket handle
        let server_handle = iface.lock().add_socket(tcp_socket);

        Ok(TCPTransport {
            iface,
            server_handle,
            server_ip,
            server_port,
            client_port,
            recv_hdr: Arc::new(Mutex::new(None)),
            send_lock: AtomicBool::new(false),
        })
    }

    fn send(&self, send_buf: &[u8]) -> Result<(), RPCError> {
        trace!("send {:?} bytes", send_buf.len());
        let mut offset = 0;

        if send_buf.is_empty() {
            return Ok(());
        }

        // Send the data
        loop {
            {
                let mut iface = self.iface.lock();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                // Send until socket state is bad (shouldn't happen), send buffer is full, all data is sent,
                // or no progress is being made (e.g., send_slice starts returning 0)
                let bytes_sent = 1;
                while socket.can_send() && bytes_sent != 0 {
                    // Attempt to send until end of data array
                    if let Ok(bytes_sent) = socket.send_slice(&send_buf[offset..]) {
                        // Try to send remaining in current send_buf
                        trace!("sent [{:?}-{:?}]", offset, offset + bytes_sent);

                        // Update index if reached end of send_buf
                        offset += bytes_sent;
                        if offset == send_buf.len() {
                            return Ok(());
                        }
                    } else {
                        trace!("send_slice failed... trying again?");
                    }
                }

                match iface.poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
            }
            for _ in 0..5 {
                core::hint::spin_loop();
            }
        }
    }

    /// Receive data from a remote node
    fn recv(&self, recv_buf: &mut [u8]) -> Result<(), RPCError> {
        trace!("recv {:?} bytes", recv_buf.len());
        let mut offset = 0;

        if recv_buf.is_empty() {
            return Ok(());
        }

        loop {
            // Recv until socket state is bad (shouldn't happen), all data is received,
            // or no progress is being made (e.g., recv_slice starts returning 0)
            {
                let mut iface = self.iface.lock();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);

                let bytes_recv = 1;
                while socket.can_recv() && bytes_recv != 0 {
                    // Attempt to recv until end of data array
                    if let Ok(bytes_recv) = socket.recv_slice(&mut recv_buf[offset..]) {
                        // Try to recv remaining in current recv_buf
                        trace!("recv [{:?}-{:?}]", offset, offset + bytes_recv);

                        // Update index if reached end of recv_buf
                        offset += bytes_recv;
                        if offset == recv_buf.len() {
                            return Ok(());
                        }
                    } else {
                        debug!("recv_slice failed... trying again?");
                    }
                }
                match iface.poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
            }
            for _ in 0..5 {
                core::hint::spin_loop();
            }
        }
    }

    fn internal_recv_msg(
        &self,
        hdr: &mut RPCHeader,
        recipient_id: Option<MsgId>,
        payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        debug!("internal_recv_msg, recipient_id = {:?}", recipient_id,);

        loop {
            // Try to grab lock
            let mut recv_hdr = self.recv_hdr.lock();
            trace!("internal_recv_msg acquired receive lock");

            let received_hdr = if let Some(r_hdr) = *recv_hdr {
                // already been received
                trace!(
                    "internal_recv_msg acquired receive lock already has header: {:?}",
                    r_hdr
                );
                r_hdr
            } else {
                // We have not already received a header.
                trace!("internal_recv_msg acquired receive lock has NO header");
                let mut new_hdr = RPCHeader::default();
                let hdr_slice = unsafe { new_hdr.as_mut_bytes() };
                self.recv(&mut hdr_slice[..])?;
                trace!("internal_recv_msg received new header: {:?}", new_hdr);
                *recv_hdr = Some(new_hdr);
                new_hdr
            };

            let is_match = match recipient_id {
                None => true,
                Some(id) => id == received_hdr.msg_id,
            };
            debug!(
                "internal_recv_msg is_match={:?}, recv_header={:?}, recipient_id={:?}",
                is_match, recv_hdr, recipient_id
            );

            if is_match {
                // Copy received header into our given header
                hdr.copy_from(received_hdr);

                // Remove the received header from partial-received status
                *recv_hdr = None;

                // We've also received all of the header so we are ready to read in all payload data.
                // First, do a bit of validation before entering loop
                let expected_data = hdr.msg_len as usize;
                let max_recv_data = payload.iter().fold(0, |acc, x| acc + x.len());
                return if expected_data > max_recv_data {
                    // Not enough space to store all message data
                    log::error!(
                        "Found {:?} payload data, but only have room for {:?}",
                        expected_data,
                        max_recv_data
                    );
                    Err(RPCError::InternalError)
                } else if expected_data == 0 {
                    trace!("internal_recv_msg done - nothing else to receive");
                    Ok(())
                } else {
                    // Receive until expected data is fully received
                    let mut recv_count = 0;
                    trace!(
                        "internal_recv_msg - about to receive {:?} into buffers",
                        expected_data
                    );
                    for p in payload.iter_mut() {
                        if recv_count + p.len() > expected_data {
                            trace!(
                                "recv_msg recv payload buf[{:?}-{:?}]",
                                0,
                                expected_data - recv_count
                            );
                            self.recv(&mut p[..(expected_data - recv_count)])?;
                            return Ok(());
                        } else {
                            trace!("recv_msg recv payload buf[{:?}-{:?}]", 0, p.len());
                            recv_count += p.len();
                            self.recv(p)?;
                        }
                    }
                    trace!(
                        "internal_recv_msg - finished receiving {:?} into buffers",
                        expected_data
                    );
                    Ok(())
                };
            } else {
                drop(recv_hdr);
                trace!("internal_recv_msg no match -> dropped receive header lock");
                // TODO: this isn't a great solution
                for _ in 0..5 {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

impl<'a, D: for<'d> Device<'d>> Transport for TCPTransport<'a, D> {
    fn max_send(&self) -> usize {
        RX_BUF_LEN
    }

    fn max_recv(&self) -> usize {
        TX_BUF_LEN
    }

    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError> {
        debug!("send_msg");

        // Set the send lock
        loop {
            if self
                .send_lock
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            } else {
                // TODO: this isn't a great solution
                for _ in 0..5 {
                    core::hint::spin_loop();
                }
            }
        }
        trace!("send_msg - acquired lock");

        if let Err(e) = self.send(&unsafe { hdr.as_bytes() }[..]) {
            self.send_lock.store(false, Ordering::SeqCst);
            trace!("send_msg - released lock on failure");
            return Err(e);
        }
        for p in payload {
            trace!("send_msg - sending payload");
            if let Err(e) = self.send(p) {
                self.send_lock.store(false, Ordering::SeqCst);
                trace!("send_msg - released lock on failure");
                return Err(e);
            }
        }
        self.send_lock.store(false, Ordering::SeqCst);
        debug!("send_msg - done");
        Ok(())
    }

    fn recv_msg(
        &self,
        hdr: &mut RPCHeader,
        recipient_id: Option<MsgId>,
        payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        trace!("recv_msg");
        self.internal_recv_msg(hdr, recipient_id, payload)?;
        Ok(())
    }

    fn send_and_recv(
        &self,
        hdr: &mut RPCHeader,
        send_payload: &[&[u8]],
        recv_payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        self.send_msg(hdr, send_payload)?;
        self.recv_msg(hdr, Some(hdr.msg_id), recv_payload)
    }

    fn client_connect(&mut self) -> Result<(), RPCError> {
        {
            let mut iface = self.iface.lock();
            let ip = self.server_ip.ok_or(RPCError::ClientInitializationError)?;
            let (socket, cx) = iface.get_socket_and_context::<TcpSocket>(self.server_handle);

            // TODO: add timeout?? with error returned if timeout occurs?
            let ret = socket.connect(cx, (ip, self.server_port), self.client_port);
            //.map_err(|e| { log::error!("{:?}", e); RPCError::ClientConnectError})?;
            match ret {
                Ok(_) => {}
                Err(e) => log::warn!("Connection error: {:?}", e),
            }
            log::warn!(
                "Attempting to connect to server {}:{}",
                ip,
                self.server_port
            );
        }

        // Connect to server, poll until connection is complete
        loop {
            {
                let mut iface = self.iface.lock();
                match iface.poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }

                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                // Waiting for send/recv forces the TCP handshake to fully complete
                if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                    //if socket.is_active() {
                    log::warn!("Connected to server, ready to send/recv data");
                    break;
                }
            }
            for _ in 0..5 {
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    fn server_accept(&mut self) -> Result<(), RPCError> {
        // Listen
        {
            let mut iface = (*self.iface).lock();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            socket
                .listen(self.server_port)
                .map_err(|_| RPCError::ServerListenError)?;
            trace!("Listening at port {}", self.server_port);
        }

        // Poll interface until connection is established
        loop {
            {
                let mut iface = self.iface.lock();
                match iface.poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }

                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                    //if socket.is_active() {
                    debug!("Connected to client!");
                    break;
                }
            }

            for _ in 0..5 {
                core::hint::spin_loop();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;

    use smoltcp::iface::{InterfaceBuilder, NeighborCache};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
    use spin::Mutex;

    use crate::rpc::MsgLen;
    use crate::transport::RPCHeader;
    use crate::transport::TCPTransport;
    use crate::transport::Transport;

    #[test]
    fn test_initialization() {
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

        TCPTransport::new(None, 10111, 10110, Arc::new(Mutex::new(iface)))
            .expect("We should be able to initialize");
    }

    #[test]
    fn test_connect() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let mut server_transport = TCPTransport::new(None, 10111, 10110, server_iface)
                .expect("We should be able to initialize");
            server_transport
                .server_accept()
                .expect("Failed to accept client connection");
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut client_transport = TCPTransport::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }

    #[test]
    fn test_send_recv() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let mut server_transport = TCPTransport::new(None, 10111, 10110, server_iface)
                .expect("We should be able to initialize");
            server_transport
                .server_accept()
                .expect("Failed to accept client connection");

            let mut hdr = RPCHeader::default();
            let mut recv_buf = [0; 10];
            for i in 0u8..10 {
                server_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");
                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], j * i);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }

                hdr.msg_len = 2;
                server_transport
                    .send_msg(&hdr, &[&[i], &[i + 1]])
                    .expect("Failed to send message");
            }
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut client_transport = TCPTransport::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            for i in 0u8..10 {
                hdr.msg_len = 5;
                client_transport
                    .send_msg(&hdr, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                    .expect("Failed to send message");
                client_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                assert_eq!(recv_buf1[0], i);
                assert_eq!(recv_buf2[0], i + 1);
            }
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }

    #[test]
    fn test_send_and_recv() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let mut server_transport = TCPTransport::new(None, 10111, 10110, server_iface)
                .expect("We should be able to initialize");
            server_transport
                .server_accept()
                .expect("Failed to accept client connection");

            let mut hdr = RPCHeader::default();
            let mut recv_buf = [0; 10];
            for i in 0u8..10 {
                server_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");
                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], j * i);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }

                hdr.msg_len = 2;
                server_transport
                    .send_msg(&hdr, &[&[i], &[i + 1]])
                    .expect("Failed to send message");
            }
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut client_transport = TCPTransport::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            for i in 0u8..10 {
                hdr.msg_len = 5;
                client_transport
                    .send_and_recv(
                        &mut hdr,
                        &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]],
                        &mut [&mut recv_buf1, &mut recv_buf2],
                    )
                    .expect("Failed to send and recv");
                assert_eq!(recv_buf1[0], i);
                assert_eq!(recv_buf2[0], i + 1);
            }
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }

    #[test]
    fn test_multi_client_server() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();
        let client2_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let mut server_transport = TCPTransport::new(None, 10111, 10110, server_iface.clone())
                .expect("We should be able to initialize");
            let mut server2_transport = TCPTransport::new(None, 10113, 10112, server_iface).expect(
                "We should be able to initialize a second transport with the same interface",
            );

            server_transport
                .server_accept()
                .expect("Failed to accept client connection");
            println!("Server1 done accepting");
            server2_transport
                .server_accept()
                .expect("Failed to accept client connection");
            println!("Server2 done accepting");

            let mut hdr = RPCHeader::default();
            let mut recv_buf = [0; 10];
            for i in 0u8..10 {
                server_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");

                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], j * i);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }
                server2_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");

                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], 1u8);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }

                hdr.msg_len = 2;
                server_transport
                    .send_msg(&hdr, &[&[i], &[i + 1]])
                    .expect("Failed to send message");
                server2_transport
                    .send_msg(&hdr, &[&[i + 1], &[i + 2]])
                    .expect("Failed to send message");
            }
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut client_transport = TCPTransport::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");
            println!("Client 1 connected");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            for i in 0u8..10 {
                hdr.msg_len = 5;
                println!("Client 1 before send");
                client_transport
                    .send_msg(&hdr, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                    .expect("Failed to send message");
                println!("Client 1 before recv");
                client_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                println!("Client 1 after recv");
                assert_eq!(recv_buf1[0], i);
                assert_eq!(recv_buf2[0], i + 1);
            }
        });

        let client2_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut client2_transport = TCPTransport::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10113,
                10112,
                client2_iface,
            )
            .expect("We should be able to initialize");
            client2_transport
                .client_connect()
                .expect("Client failed to connect to server");
            println!("Client 2 connected");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            // Send 2, then receive 2
            for i in 0u8..5 {
                hdr.msg_len = 5;
                println!("Client 2 before send1");
                client2_transport
                    .send_msg(&hdr, &[&[1, 1, 1, 1, 1]])
                    .expect("Failed to send message");
                println!("Client 2 before send2");
                client2_transport
                    .send_msg(&hdr, &[&[1, 1, 1, 1, 1]])
                    .expect("Failed to send message");
                println!("Client 2 before recv1");
                client2_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                assert_eq!(recv_buf1[0], (i * 2) + 1);
                assert_eq!(recv_buf2[0], (i * 2) + 2);
                println!("Client 2 before recv2");
                client2_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                println!("Client 2 after recv2");
                assert_eq!(recv_buf1[0], (i * 2 + 1) + 1);
                assert_eq!(recv_buf2[0], (i * 2 + 1) + 2);
            }
        });

        client_thread.join().unwrap();
        client2_thread.join().unwrap();
        server_thread.join().unwrap();
    }
}
