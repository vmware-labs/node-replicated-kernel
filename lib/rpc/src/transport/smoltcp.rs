// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
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
    iface: Arc<RefCell<Interface<'a, DevQueuePhy>>>,
    server_handle: SocketHandle,
    server_ip: Option<IpAddress>,
    server_port: u16,
    client_port: u16,
}

impl TCPTransport<'_> {
    pub fn new(
        server_ip: Option<IpAddress>,
        server_port: u16,
        iface: Arc<RefCell<Interface<'_, DevQueuePhy>>>,
    ) -> TCPTransport<'_> {
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

        // Add socket to interface and record socket handle
        let server_handle = iface.borrow_mut().add_socket(tcp_socket);

        TCPTransport {
            iface,
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

    fn send(&self, send_bufs: &[&[u8]]) -> Result<(), RPCError> {
        // Calculate and check total data to receive
        let send_data_len = send_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(send_data_len <= self.max_send());

        trace!("Attempting to send {:?} bytes", send_data_len);
        if send_data_len == 0 {
            return Ok(());
        }

        // Read in all msg data
        let mut data_sent = 0;
        let mut index = 0;
        let mut offset = 0;
        loop {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Send until socket state is bad (shouldn't happen), send buffer is full, all data is sent,
            // or no progress is being made (e.g., send_slice starts returning 0)
            let bytes_sent = 1;
            while socket.can_send() && data_sent < send_data_len && bytes_sent != 0 {
                // Attempt to send until end of data array
                if let Ok(bytes_sent) = socket.send_slice(&send_bufs[index][offset..]) {
                    // Try to send remaining in current send_buf
                    trace!("sent [{:?}][{:?}-{:?}]", index, offset, offset + bytes_sent);
                    data_sent += bytes_sent;

                    // Check if done
                    if data_sent == send_data_len {
                        return Ok(());
                    }

                    // Update index if reached end of send_buf
                    if offset + bytes_sent == send_bufs[index].len() {
                        index += 1;
                        offset = 0;
                    } else {
                        offset += bytes_sent;
                    }
                } else {
                    trace!("send_slice failed... trying again?");
                }
            }

            // Poll the interface only if we must in order to have space in the send buffer
            {
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

    fn try_send(&self, send_bufs: &[&[u8]]) -> Result<bool, RPCError> {
        // Calculate and check total data to receive
        let send_data_len = send_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(send_data_len <= self.max_send());

        trace!("Attempting to try_send {:?} bytes", send_data_len);
        if send_data_len == 0 {
            return Ok(true);
        }

        let mut iface = self.iface.borrow_mut();
        let socket = iface.get_socket::<TcpSocket>(self.server_handle);

        // Attempt to write from first buffer into the socket send buffer
        let bytes_sent = match socket.can_send() {
            true => match socket.send_slice(&send_bufs[0]) {
                Ok(bytes_sent) => {
                    trace!("try_send [{:?}][{:?}-{:?}]", 0, 0, bytes_sent);
                    bytes_sent
                }
                Err(_) => 0,
            },
            false => 0,
        };

        // Can't send now
        if bytes_sent == 0 {
            return Ok(false);

        // If we started sending, send (with blocking) remaining data
        } else if bytes_sent == send_bufs[0].len() {
            if send_bufs.len() > 1 {
                self.send(&send_bufs[1..])?;
            }
            return Ok(true);
        }

        // For highest efficiency, if we only sent part of the buffer,
        // We don't want to split up into two sends so do send code here
        let mut data_sent = bytes_sent;
        let mut index = 0;
        let mut offset = 0;
        loop {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Send until socket state is bad (shouldn't happen), send buffer is full, all data is sent,
            // or no progress is being made (e.g., send_slice starts returning 0)
            let bytes_sent = 1;
            while socket.can_send() && data_sent < send_data_len && bytes_sent != 0 {
                // Attempt to send until end of data array
                if let Ok(bytes_sent) = socket.send_slice(&send_bufs[index][offset..]) {
                    // Try to send remaining in current send_buf
                    trace!("sent [{:?}][{:?}-{:?}]", index, offset, offset + bytes_sent);
                    data_sent += bytes_sent;

                    // Check if done
                    if data_sent == send_data_len {
                        return Ok(true);
                    }

                    // Update index if reached end of send_buf
                    if offset + bytes_sent == send_bufs[index].len() {
                        index += 1;
                        offset = 0;
                    } else {
                        offset += bytes_sent;
                    }
                } else {
                    trace!("send_slice failed... trying again?");
                }
            }

            // Poll the interface only if we must in order to have space in the send buffer
            {
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
    fn recv(&self, recv_bufs: &mut [&mut [u8]]) -> Result<(), RPCError> {
        // Calculate and check total data to receive
        let recv_data_len = recv_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(recv_data_len <= self.max_recv());

        trace!("Attempting to recv {:?} bytes", recv_data_len);
        if recv_data_len == 0 {
            return Ok(());
        }

        // Recv all data
        let mut data_recv = 0;
        let mut index = 0;
        let mut offset = 0;
        loop {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Recv until socket state is bad (shouldn't happen), all data is received,
            // or no progress is being made (e.g., recv_slice starts returning 0)
            let bytes_recv = 1;
            while socket.can_recv() && data_recv < recv_data_len && bytes_recv != 0 {
                // Attempt to recv until end of data array
                if let Ok(bytes_recv) = socket.recv_slice(&mut recv_bufs[index][offset..]) {
                    // Try to recv remaining in current recv_buf
                    trace!("recv [{:?}][{:?}-{:?}]", index, offset, offset + bytes_recv);
                    data_recv += bytes_recv;

                    // Check if done
                    if data_recv == recv_data_len {
                        return Ok(());
                    }

                    // Update index if reached end of recv_buf
                    if offset + bytes_recv == recv_bufs[index].len() {
                        index += 1;
                        offset = 0;
                    } else {
                        offset += bytes_recv;
                    }
                } else {
                    trace!("recv_slice failed... trying again?");
                }
            }

            // Poll the interface only if we must in order to have space in the send buffer
            {
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

    fn try_recv(&self, recv_bufs: &mut [&mut [u8]]) -> Result<bool, RPCError> {
        // Calculate and check total data to receive
        let recv_data_len = recv_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(recv_data_len <= self.max_recv());

        trace!("Attempting to try_recv {:?} bytes", recv_data_len);
        if recv_data_len == 0 {
            return Ok(true);
        }

        let mut iface = self.iface.borrow_mut();
        let socket = iface.get_socket::<TcpSocket>(self.server_handle);

        // Attempt to write to the first buffer from the socket receive buffer
        let bytes_recv = match socket.can_recv() {
            true => {
                if let Ok(bytes_recv) = socket.recv_slice(&mut recv_bufs[0]) {
                    trace!("try_recv [{:?}][{:?}-{:?}]", 0, 0, bytes_recv);
                    bytes_recv
                } else {
                    0
                }
            }
            false => 0,
        };

        // Can't receive now
        if bytes_recv == 0 {
            return Ok(false);

        // If we started receiving, receive (with blocking) remaining data
        } else if bytes_recv == recv_bufs[0].len() {
            if recv_bufs.len() > 1 {
                self.recv(&mut recv_bufs[1..])?;
            }
            return Ok(true);
        }

        // For highest efficiency, if we only received part of the buffer,
        // We don't want to split up into two receives so do remaining receive code here
        let mut data_recv = bytes_recv;
        let mut index = 0;
        let mut offset = 0;
        loop {
            let mut iface = self.iface.borrow_mut();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Receive until socket state is bad (shouldn't happen), all data is received,
            // or no progress is being made (e.g., recv_slice starts returning 0)
            let bytes_recv = 1;
            while socket.can_recv() && data_recv < recv_data_len && bytes_recv != 0 {
                // Attempt to recv until end of data array
                if let Ok(bytes_recv) = socket.recv_slice(&mut recv_bufs[index][offset..]) {
                    // Try to recv remaining in current recv_buf
                    trace!("recv [{:?}][{:?}-{:?}]", index, offset, offset + bytes_recv);
                    data_recv += bytes_recv;

                    // Check if done
                    if data_recv == recv_data_len {
                        return Ok(true);
                    }

                    // Update index if reached end of recv_buf
                    if offset + bytes_recv == recv_bufs[index].len() {
                        index += 1;
                        offset = 0;
                    } else {
                        offset += bytes_recv;
                    }
                } else {
                    trace!("recv _slice failed... trying again?");
                }
            }

            // Poll the interface only if we must in order to have space in the recv buffer
            {
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

    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError> {
        // TODO: send all at once for small performance increase
        self.send(&[&unsafe { hdr.as_bytes() }[..]])?;
        self.send(payload)
    }

    fn try_send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<bool, RPCError> {
        // TODO: send all at once for small performance increase
        match self.try_send(&[&unsafe { hdr.as_bytes() }[..]])? {
            true => {
                self.send(payload)?;
                Ok(true)
            }
            false => Ok(false),
        }
    }

    fn recv_msg(&self, hdr: &mut RPCHeader, payload: &mut [&mut [u8]]) -> Result<(), RPCError> {
        // Calculate and check total data_out len
        let data_out_len = payload.iter().fold(0, |acc, x| acc + x.len());
        assert!(data_out_len + HDR_LEN <= self.max_send());

        // Receive the header
        {
            let hdr_slice = unsafe { hdr.as_mut_bytes() };
            self.recv(&mut [hdr_slice])?;
        }

        // Read header to determine how much message data we're expecting
        let total_msg_data = hdr.msg_len as usize;
        assert!(total_msg_data <= data_out_len);

        // Fill all data
        if total_msg_data == data_out_len {
            self.recv(payload)?;

        // Partial fill
        } else {
            let mut recv_space = 0;
            let mut index = 0;
            loop {
                if payload[index].len() <= total_msg_data - recv_space {
                    recv_space += payload[index].len();
                    index += 1;
                } else {
                    break;
                }
            }
            self.recv(&mut payload[..index])?;
            if recv_space < total_msg_data {
                self.recv(&mut [&mut payload[index][..(total_msg_data - recv_space)]])?;
            }
        }
        Ok(())
    }

    fn try_recv_msg(
        &self,
        hdr: &mut RPCHeader,
        payload: &mut [&mut [u8]],
    ) -> Result<bool, RPCError> {
        // Calculate and check total data_out len
        let data_out_len = payload.iter().fold(0, |acc, x| acc + x.len());
        assert!(data_out_len + HDR_LEN <= self.max_send());

        // Try to receive the header
        {
            let hdr_slice = unsafe { hdr.as_mut_bytes() };
            if !self.try_recv(&mut [hdr_slice])? {
                return Ok(false);
            }
        }

        // Read header to determine how much message data we're expecting
        let total_msg_data = hdr.msg_len as usize;
        assert!(total_msg_data <= data_out_len);

        // Fill all data
        if total_msg_data == data_out_len {
            self.recv(payload)?;

        // Partial fill
        } else {
            let mut recv_space = 0;
            let mut index = 0;
            loop {
                if payload[index].len() <= total_msg_data - recv_space {
                    recv_space += payload[index].len();
                    index += 1;
                } else {
                    break;
                }
            }
            self.recv(&mut payload[..index])?;
            if recv_space < total_msg_data {
                self.recv(&mut [&mut payload[index][..(total_msg_data - recv_space)]])?;
            }
        }
        Ok(true)
    }

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
