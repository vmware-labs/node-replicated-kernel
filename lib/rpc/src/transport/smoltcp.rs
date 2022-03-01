// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::cell::RefCell;
use log::{debug, warn};

use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;

use vmxnet3::smoltcp::DevQueuePhy;

use crate::rpc::*;
use crate::transport::Transport;

const RX_BUF_LEN: usize = 8192;
const TX_BUF_LEN: usize = 8192;

pub struct TCPTransport<'a> {
    iface: RefCell<Interface<'a, DevQueuePhy>>,
    server_handle: SocketHandle,
    server_ip: Option<IpAddress>,
    server_port: u16,
    client_port: u16,
}

impl TCPTransport<'_> {
    pub fn new<'a>(
        server_ip: Option<IpAddress>,
        server_port: u16,
        iface: Interface<'a, DevQueuePhy>,
    ) -> TCPTransport<'a> {
        lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);
        lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);

        // Create RX and TX buffers for the socket
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(RX_BUF_LEN).unwrap();
        sock_vec.resize(RX_BUF_LEN, 0);
        let socket_rx_buffer = TcpSocketBuffer::new(sock_vec);
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(TX_BUF_LEN).unwrap();
        sock_vec.resize(TX_BUF_LEN, 0);

        // Create the TCP socket
        let socket_tx_buffer = TcpSocketBuffer::new(sock_vec);
        let mut tcp_socket = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);
        tcp_socket.set_ack_delay(None);

        // Create wrapper for iface
        let iface_ref = RefCell::new(iface);

        // Add to sockets and remember socket handle
        let server_handle = iface_ref.borrow_mut().add_socket(tcp_socket);

        TCPTransport {
            iface: iface_ref,
            server_handle,
            server_ip,
            server_port,
            client_port: 10110,
        }
    }
}

impl Transport for TCPTransport<'_> {
    fn max_send(&self) -> usize {
        RX_BUF_LEN
    }

    fn max_recv(&self) -> usize {
        TX_BUF_LEN
    }

    /// send data to a remote node
    fn send(&self, expected_data: usize, data_buff: &[u8]) -> Result<(), RPCError> {
        let mut data_sent = 0;
        assert!(expected_data <= data_buff.len());
        if expected_data == 0 {
            return Ok(());
        }
        debug!("Attempting to send {:?} bytes", expected_data);

        loop {
            {
                let mut iface = self.iface.borrow_mut();
                match iface.poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
            }

            if data_sent == expected_data {
                return Ok(());
            } else {
                let mut iface = self.iface.borrow_mut();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                if socket.can_send() && data_sent < expected_data {
                    if let Ok(bytes_sent) = socket.send_slice(&data_buff[data_sent..expected_data])
                    {
                        debug!("sent [{:?}-{:?}]", data_sent, data_sent + bytes_sent,);
                        data_sent += bytes_sent;
                    } else {
                        debug!("send_slice failed... trying again?");
                    }
                }
            }
        }
    }

    /// receive data from a remote node
    fn recv(&self, expected_data: usize, data_buff: &mut [u8]) -> Result<(), RPCError> {
        let mut data_received = 0;

        // Check write size - make sure it fits in buffer
        assert!(expected_data <= data_buff.len());

        if expected_data == 0 {
            return Ok(());
        }
        debug!("Attempting to receive {:?} bytes", expected_data);

        loop {
            {
                let mut iface = self.iface.borrow_mut();
                match iface.poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
            }

            if data_received == expected_data {
                return Ok(());
            } else {
                let mut iface = self.iface.borrow_mut();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                if socket.can_recv() && data_received < expected_data {
                    if let Ok(bytes_received) =
                        socket.recv_slice(&mut data_buff[data_received..expected_data])
                    {
                        debug!(
                            "recv [{:?}-{:?}]",
                            data_received,
                            data_received + bytes_received
                        );
                        data_received += bytes_received;
                    } else {
                        warn!("recv_slice failed... trying again?");
                    }
                }
            }
        }
    }

    /// Register with controller, analogous to LITE join_cluster()
    /// TODO: add timeout?? with error returned if timeout occurs?
    fn client_connect(&mut self) -> Result<(), RPCError> {
        {
            let mut iface = self.iface.borrow_mut();
            let (socket, cx) = iface.get_socket_and_context::<TcpSocket>(self.server_handle);
            socket
                .connect(
                    cx,
                    (self.server_ip.unwrap(), self.server_port),
                    self.client_port,
                )
                .unwrap();
            debug!(
                "Attempting to connect to server {}:{}",
                self.server_ip.unwrap(),
                self.server_port
            );
        }

        // Connect to server
        {
            loop {
                match self.iface.borrow_mut().poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
                let mut iface = self.iface.borrow_mut();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                // Waiting for send/recv forces the TCP handshake to fully complete
                if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                    debug!("Connected to server, ready to send/recv data");
                    break;
                }
            }
        }
        Ok(())
    }

    fn server_accept(&self) -> Result<(), RPCError> {
        // Add to sockets
        {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            socket.listen(self.server_port).unwrap();
            debug!("Listening at port {}", self.server_port);
        }

        loop {
            match self.iface.borrow_mut().poll(Instant::from_millis(
                rawtime::duration_since_boot().as_millis() as i64,
            )) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            // This is equivalent (more or less) to accept
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                debug!("Connected to client!");
                break;
            }
        }
        Ok(())
    }
}
