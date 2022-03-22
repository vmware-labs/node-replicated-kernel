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
    fn send(&self, data_out: &[&[u8]]) -> Result<(), RPCError> {
        let mut data_sent = 0;
        let mut list_index = 0;
        let mut data_index = 0;

        if data_out.len() == 0 {
            return Ok(());
        }
        for d in data_out.iter() {
            debug!("Attempting to send {:?} bytes", d.len());
        }

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

            if list_index == data_out.len() {
                debug!("Send complete");
                return Ok(());
            } else {
                let mut iface = self.iface.borrow_mut();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);

                let max_send = socket.send_capacity() - socket.send_queue();
                let bytes_sent = 1;
                //debug!("can_send={:?}, max_send={:?}, data_sent={:?}, list_index={:?}, list_len={:?}, bytes_sent={:?}")

                // Send until socket is bad (shouldn't happen), send buffer is full, all data is sent,
                // or no progress is being made (e.g., send_slice starts returning 0)
                while socket.can_send()
                    && (data_sent < max_send)
                    && list_index < data_out.len()
                    && bytes_sent != 0
                {
                    // Send until end of current data array or until send buffer is full
                    let end_index = core::cmp::min(
                        data_out[list_index].len(),
                        data_index + (max_send - data_sent),
                    );

                    // Actually attempt to write to out buffer
                    if let Ok(bytes_sent) =
                        socket.send_slice(&data_out[list_index][data_index..end_index])
                    {
                        debug!(
                            "sent [{:?}][{:?}-{:?}]",
                            list_index,
                            data_index,
                            data_index + bytes_sent
                        );
                        data_sent += bytes_sent;
                        if end_index >= data_out[list_index].len() {
                            list_index += 1;
                            data_index = 0;
                        } else {
                            data_index += bytes_sent;
                        }
                    } else {
                        debug!("send_slice failed... trying again?");
                    }
                }
                debug!("Wrote {:?} bytes to the send buffer", data_sent);
                data_sent = 0;
            }
        }
    }

    /// send data to a remote node
    fn send_msg(&self, hdr_out: &RPCHeader, data_out: &[&[u8]]) -> Result<(), RPCError> {
        let mut list_index = 0;
        let mut data_index = 0;
        let mut hdr_sent = false;

        let hdr_slice = unsafe { hdr_out.as_bytes() };

        loop {
            if hdr_sent && list_index == data_out.len() {
                debug!("Send complete");
                return Ok(());
            } else {
                let mut iface = self.iface.borrow_mut();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                let bytes_sent = 1;

                // Send until socket is bad (shouldn't happen), send buffer is full, all data is sent,
                // or no progress is being made (e.g., send_slice starts returning 0)
                while socket.can_send()
                    && (!hdr_sent || list_index < data_out.len())
                    && bytes_sent != 0
                {
                    // Actually attempt to write to out buffer
                    if !hdr_sent {
                        if let Ok(bytes_sent) = socket.send_slice(&hdr_slice[data_index..HDR_LEN]) {
                            debug!("sent hdr {:?}", bytes_sent);
                            if bytes_sent == HDR_LEN {
                                hdr_sent = true;
                                data_index = 0;
                                debug!("Header sent!");
                            } else {
                                data_index += bytes_sent;
                            }
                        } else {
                            debug!("send_slice failed... trying again?");
                        }
                    }
                    if hdr_sent && data_out.len() > 0 {
                        // Attempt to send until end of current data array
                        let end_index = data_out[list_index].len();

                        if let Ok(bytes_sent) =
                            socket.send_slice(&data_out[list_index][data_index..end_index])
                        {
                            debug!(
                                "sent [{:?}][{:?}-{:?}]",
                                list_index,
                                data_index,
                                data_index + bytes_sent
                            );
                            data_index += bytes_sent;
                            if data_index >= data_out[list_index].len() {
                                list_index += 1;
                                data_index = 0;
                            }
                        } else {
                            debug!("send_slice failed... trying again?");
                        }
                    }
                }
            }

            // Poll the interface
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

    /// receive data from a remote node
    fn recv(&self, expected_data: usize, data_in: &mut [&mut [u8]]) -> Result<(), RPCError> {
        let mut list_index = 0;
        let mut data_index = 0;
        let mut total_received = 0;
        let data_arr_len = data_in.len();

        if data_arr_len == 0 {
            return Ok(());
        }
        for d in data_in.iter() {
            debug!("Attempting to recv {:?} bytes", d.len());
        }

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

            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            let bytes_received = 1;

            while socket.can_recv()
                && list_index < data_arr_len
                && socket.recv_queue() > 0
                && bytes_received > 0
                && total_received < expected_data
            {
                let end_index =
                    core::cmp::min(data_in[list_index].len(), expected_data - total_received);
                if let Ok(bytes_received) =
                    socket.recv_slice(&mut data_in[list_index][data_index..end_index])
                {
                    debug!(
                        "recv [{:?}][{:?}-{:?}] {:?}",
                        list_index,
                        data_index,
                        end_index,
                        data_in[list_index].len()
                    );
                    data_index += bytes_received;
                    total_received += bytes_received;
                    if data_index == data_in[list_index].len() {
                        list_index += 1;
                        data_index = 0;
                        debug!("Incremented list index: {:?}", list_index);
                    }
                    if list_index == data_arr_len || total_received == expected_data {
                        return Ok(());
                    }
                } else {
                    warn!("recv_slice failed... trying again?");
                }
            }
        }
    }

    /// receive data from a remote node
    fn recv_msg(&self, hdr_in: &mut RPCHeader, data_in: &mut [&mut [u8]]) -> Result<(), RPCError> {
        let mut list_index = 0;
        let mut data_index = 0;
        let mut total_received = 0;
        let mut msg_len = 0;
        let mut hdr_received = false;

        loop {
            {
                let mut iface = self.iface.borrow_mut();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);
                let bytes_received = 1;

                while socket.can_recv()
                    && (!hdr_received || total_received < msg_len)
                    && bytes_received > 0
                {
                    if !hdr_received {
                        let hdr_slice = unsafe { hdr_in.as_mut_bytes() };
                        if let Ok(bytes_received) =
                            socket.recv_slice(&mut hdr_slice[data_index..HDR_LEN])
                        {
                            debug!("recv hdr {:?}", bytes_received);
                            if bytes_received == HDR_LEN {
                                hdr_received = true;
                                data_index = 0;
                                debug!("Header received! msg_len = {:?}", msg_len);
                            } else {
                                data_index += bytes_received;
                            }
                        } else {
                            warn!("recv_slice failed... trying again?");
                        }

                        if hdr_received {
                            msg_len = hdr_in.msg_len as usize;
                            if msg_len == 0 {
                                return Ok(());
                            }
                        }
                    }

                    if hdr_received && msg_len > 0 {
                        let end_index =
                            core::cmp::min(data_in[list_index].len(), msg_len - total_received);
                        if let Ok(bytes_received) =
                            socket.recv_slice(&mut data_in[list_index][data_index..end_index])
                        {
                            debug!(
                                "recv [{:?}][{:?}-{:?}] {:?}",
                                list_index,
                                data_index,
                                end_index,
                                data_in[list_index].len()
                            );
                            data_index += bytes_received;
                            total_received += bytes_received;
                            if data_index == data_in[list_index].len() {
                                list_index += 1;
                                data_index = 0;
                            }
                            if total_received == msg_len {
                                return Ok(());
                            }
                        } else {
                            warn!("recv_slice failed... trying again?");
                        }
                    }
                }
            }

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
