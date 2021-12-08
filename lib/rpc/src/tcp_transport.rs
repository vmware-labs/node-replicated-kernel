// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::cell::RefCell;
use log::{debug, warn};

use smoltcp::iface::EthernetInterface;
use smoltcp::socket::{SocketHandle, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;

use vmxnet3::smoltcp::DevQueuePhy;

use crate::rpc::*;
use crate::rpc_api::RPCTransport;

const RX_BUF_LEN: usize = 8192;
const TX_BUF_LEN: usize = 8192;

pub struct TCPTransport<'a> {
    iface: RefCell<EthernetInterface<'a, DevQueuePhy>>,
    sockets: RefCell<SocketSet<'a>>,
    server_handle: Option<SocketHandle>,
    server_ip: IpAddress,
    server_port: u16,
    client_port: u16,
}

impl TCPTransport<'_> {
    pub fn new(
        server_ip: IpAddress,
        server_port: u16,
        iface: EthernetInterface<'_, DevQueuePhy>,
    ) -> TCPTransport<'_> {
        // Create SocketSet w/ space for 1 socket
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(1).unwrap();
        let sockets = SocketSet::new(sock_vec);

        TCPTransport {
            iface: RefCell::new(iface),
            sockets: RefCell::new(sockets),
            server_handle: None,
            server_ip,
            server_port,
            client_port: 10110,
        }
    }
}

impl RPCTransport for TCPTransport<'_> {
    fn max_send(&self) -> usize {
        return RX_BUF_LEN;
    }

    fn max_recv(&self) -> usize {
        return TX_BUF_LEN;
    }

    /// send data to a remote node
    fn send(&self, expected_data: usize, data_buff: &[u8]) -> Result<(), RPCError> {
        let mut data_sent = 0;
        assert!(expected_data <= data_buff.len());

        let mut sockets = self.sockets.borrow_mut();
        loop {
            match self
                .iface
                .borrow_mut()
                .poll(&mut sockets, Instant::from_millis(0))
            {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            if data_sent == expected_data {
                return Ok(());
            } else {
                let mut socket = sockets.get::<TcpSocket>(self.server_handle.unwrap());
                if socket.can_send() && socket.send_capacity() > 0 && data_sent < expected_data {
                    let end_index =
                        data_sent + core::cmp::min(expected_data, socket.send_capacity());
                    if let Ok(bytes_sent) = socket.send_slice(&data_buff[data_sent..end_index]) {
                        debug!(
                            "sent: [{:?}-{:?}] {:?}/{:?} bytes",
                            data_sent, end_index, end_index, expected_data
                        );
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
        let mut total_data_received = 0;

        // Check write size - make sure it fits in buffer
        assert!(expected_data <= data_buff.len());

        let mut sockets = self.sockets.borrow_mut();
        loop {
            match self
                .iface
                .borrow_mut()
                .poll(&mut sockets, Instant::from_millis(0))
            {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            if total_data_received == expected_data {
                return Ok(());
            } else {
                let mut socket = sockets.get::<TcpSocket>(self.server_handle.unwrap());
                if socket.can_recv() {
                    if let Ok(bytes_received) =
                        socket.recv_slice(&mut data_buff[total_data_received..expected_data])
                    {
                        total_data_received += bytes_received;
                        debug!(
                            "rcv got {:?}/{:?} bytes",
                            total_data_received, expected_data
                        );
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
        // create client socket
        // Create RX and TX buffers for the socket
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(RX_BUF_LEN).unwrap();
        sock_vec.resize(RX_BUF_LEN, 0);
        let socket_rx_buffer = TcpSocketBuffer::new(sock_vec);
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(TX_BUF_LEN).unwrap();
        sock_vec.resize(TX_BUF_LEN, 0);
        let socket_tx_buffer = TcpSocketBuffer::new(sock_vec);
        let tcp_socket = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);

        // Add to sockets
        {
            let mut sockets = self.sockets.borrow_mut();
            self.server_handle = Some(sockets.add(tcp_socket));
        }

        {
            let mut sockets = self.sockets.borrow_mut();
            let mut socket = sockets.get::<TcpSocket>(self.server_handle.unwrap());
            socket
                .connect((self.server_ip, self.server_port), self.client_port)
                .unwrap();
            debug!(
                "Attempting to connect to server {}:{}",
                self.server_ip, self.server_port
            );
        }

        // Connect to server
        {
            let mut sockets = self.sockets.borrow_mut();
            loop {
                match self
                    .iface
                    .borrow_mut()
                    .poll(&mut sockets, Instant::from_millis(0))
                {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
                let socket = sockets.get::<TcpSocket>(self.server_handle.unwrap());
                // Waiting for send/recv forces the TCP handshake to fully complete
                if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                    debug!("Connected to server, ready to send/recv data");
                    break;
                }
            }
        }
        Ok(())
    }

    fn server_accept(&mut self) -> Result<(), RPCError> {
        let mut sockets = self.sockets.borrow_mut();
        loop {
            match self
                .iface
                .borrow_mut()
                .poll(&mut sockets, Instant::from_millis(0))
            {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            // This is equivalent (more or less) to accept
            let socket = sockets.get::<TcpSocket>(self.server_handle.unwrap());
            if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                debug!("Connected to client!");
                break;
            }
        }
        Ok(())
    }
}
