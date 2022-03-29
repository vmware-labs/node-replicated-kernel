// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::cell::RefCell;
use log::{debug, trace, warn};

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

        // Add socket to interface and record socket handle
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

    /// Send data to a remote node
    fn send(&self, data_out: &[u8]) -> Result<(), RPCError> {
        let mut data_index = 0;

        trace!("Attempting to send {:?} bytes", data_out.len());
        if data_out.len() == 0 {
            return Ok(());
        }

        loop {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Send until socket state is bad (shouldn't happen), send buffer is full, all data is sent,
            // or no progress is being made (e.g., send_slice starts returning 0)
            let bytes_sent = 1;
            while socket.can_send() && data_index < data_out.len() && bytes_sent != 0 {
                // Attempt to send until end of data array
                if let Ok(bytes_sent) = socket.send_slice(&data_out[data_index..]) {
                    trace!("sent [{:?}-{:?}]", data_index, data_index + bytes_sent);
                    data_index += bytes_sent;
                    if data_index == data_out.len() {
                        return Ok(());
                    }
                } else {
                    trace!("send_slice failed... trying again?");
                }
            }

            // Poll the interface only if we must in order to have space in the send buffer
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
        }
    }

    /// Receive data from a remote node
    fn recv(&self, data_in: &mut [u8]) -> Result<(), RPCError> {
        let mut data_index = 0;

        trace!("Attempting to recv {:?} bytes", data_in.len());
        if data_in.len() == 0 {
            return Ok(());
        }

        loop {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Receive as much data as possible before polling
            let bytes_received = 1;
            while socket.can_recv()                 // socket in good state to receive
                && bytes_received > 0               // first iter or read something during previous iter
                && data_index < data_in.len()
            {
                if let Ok(bytes_received) = socket.recv_slice(&mut data_in[data_index..]) {
                    trace!(
                        "recv [{:?}-{:?}] {:?}",
                        data_index,
                        data_in.len(),
                        bytes_received
                    );

                    // Update count
                    data_index += bytes_received;

                    // Exit if finished receiving data
                    if data_index == data_in.len() {
                        return Ok(());
                    }
                } else {
                    warn!("recv_slice failed... trying again?");
                }
            }

            // Only poll if we must in order to fill receive buffer
            match iface.poll(Instant::from_millis(
                rawtime::duration_since_boot().as_millis() as i64,
            )) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }
        }
    }

    /// Register with controller, analogous to LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError> {
        {
            let mut iface = self.iface.borrow_mut();
            let (socket, cx) = iface.get_socket_and_context::<TcpSocket>(self.server_handle);

            // TODO: add timeout?? with error returned if timeout occurs?
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

        // Connect to server, poll until connection is complete
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
        // Listen
        {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            socket.listen(self.server_port).unwrap();
            debug!("Listening at port {}", self.server_port);
        }

        // Poll interface until connection is established
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
