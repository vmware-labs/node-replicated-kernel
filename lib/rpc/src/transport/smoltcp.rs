// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;
use log::{debug, trace, warn};
use spin::Mutex;

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
    iface: Arc<Mutex<Interface<'a, DevQueuePhy>>>,
    server_handle: SocketHandle,
    server_ip: Option<IpAddress>,
    server_port: u16,
    client_port: u16,
}

impl TCPTransport<'_> {
    pub fn new(
        server_ip: Option<IpAddress>,
        server_port: u16,
        iface: Arc<Mutex<Interface<'_, DevQueuePhy>>>,
    ) -> Result<TCPTransport<'_>, RPCError> {
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
        let mut tcp_socket = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);
        tcp_socket.set_ack_delay(None);

        // Add socket to interface and record socket handle
        let server_handle = iface.lock().add_socket(tcp_socket);

        Ok(TCPTransport {
            iface,
            server_handle,
            server_ip,
            server_port,
            client_port: 10110,
        })
    }

    fn send(&self, send_buf: &[u8], is_try: bool) -> Result<bool, RPCError> {
        trace!("send {:?} bytes, try={:?}", send_buf.len(), is_try);
        let mut offset = 0;

        if send_buf.is_empty() {
            return Ok(true);
        }

        {
            let mut iface = self.iface.lock();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);

            // Attempt to write from first buffer into the socket send buffer
            if socket.can_send() {
                if let Ok(bytes_sent) = socket.send_slice(send_buf) {
                    trace!("send [{:?}-{:?}]", 0, bytes_sent);
                    offset = bytes_sent;
                }
            }
        }

        // Can't send now
        if is_try && offset == 0 {
            return Ok(false);

        // All sent
        } else if offset == send_buf.len() {
            return Ok(true);
        }

        // Send rest of the data
        loop {
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
                        return Ok(true);
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
    fn recv(&self, recv_buf: &mut [u8]) -> Result<(), RPCError> {
        trace!("recv {:?} bytes", recv_buf.len());
        let mut offset = 0;

        if recv_buf.is_empty() {
            return Ok(());
        }

        loop {
            // Recv until socket state is bad (shouldn't happen), all data is received,
            // or no progress is being made (e.g., recv_slice starts returning 0)
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

    fn recv_msg(
        &self,
        hdr: &mut RPCHeader,
        payload: &mut [&mut [u8]],
        is_try: bool,
    ) -> Result<bool, RPCError> {
        // Try to receive the header, bail if try and data was not received here. Otherwise, proceed
        // to finish receiving
        trace!("recv_msg, try = {:?}", is_try);
        let mut offset = 0;
        {
            let mut iface = self.iface.lock();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            if socket.can_recv() {
                let hdr_slice = unsafe { hdr.as_mut_bytes() };
                if let Ok(bytes_recv) = socket.recv_slice(hdr_slice) {
                    trace!("recv_msg [{:?}-{:?}]", 0, bytes_recv);
                    if is_try && bytes_recv == 0 {
                        return Ok(false);
                    }
                    offset = bytes_recv;
                }
            } else if is_try {
                return Ok(false);
            }
        }

        // Finish receiving header if necessary
        let hdr_slice = unsafe { hdr.as_mut_bytes() };
        self.recv(&mut hdr_slice[offset..])?;

        // At this point, if try failed, we've already bailed. We've also received all of the header
        // So we are ready to read in all payload data. First, do a bit of validation before entering loop
        let expected_data = hdr.msg_len as usize;
        let max_recv_data = payload.iter().fold(0, |acc, x| acc + x.len());
        if expected_data > max_recv_data {
            // Not enough space to store all message data
            log::error!(
                "Found {:?} payload data, but only have room for {:?}",
                expected_data,
                max_recv_data
            );
            Err(RPCError::InternalError)
        } else if expected_data == 0 {
            Ok(true)
        } else {
            // Receive until expected data is fully received
            let mut recv_count = 0;
            for p in payload.iter_mut() {
                if recv_count + p.len() > expected_data {
                    trace!(
                        "recv_msg recv payload buf[{:?}-{:?}]",
                        0,
                        expected_data - recv_count
                    );
                    self.recv(&mut p[..(expected_data - recv_count)])?;
                    return Ok(true);
                } else {
                    trace!("recv_msg recv payload buf[{:?}-{:?}]", 0, p.len());
                    recv_count += p.len();
                    self.recv(p)?;
                }
            }
            Ok(true)
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

    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError> {
        trace!("send_msg - sending header");
        self.send(&unsafe { hdr.as_bytes() }[..], false)?;
        for p in payload {
            trace!("send_msg - sending payload");
            self.send(p, false)?;
        }
        Ok(())
    }

    fn try_send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<bool, RPCError> {
        trace!("try_send_msg - sending header");
        match self.send(&unsafe { hdr.as_bytes() }[..], true)? {
            true => {
                for p in payload {
                    trace!("send_msg - sending payload");
                    self.send(p, false)?;
                }
                Ok(true)
            }
            false => Ok(false),
        }
    }

    fn recv_msg(&self, hdr: &mut RPCHeader, payload: &mut [&mut [u8]]) -> Result<(), RPCError> {
        trace!("recv_msg");
        self.recv_msg(hdr, payload, false)?;
        Ok(())
    }

    fn try_recv_msg(
        &self,
        hdr: &mut RPCHeader,
        payload: &mut [&mut [u8]],
    ) -> Result<bool, RPCError> {
        trace!("try_recv_msg");
        self.recv_msg(hdr, payload, true)
    }

    fn client_connect(&mut self) -> Result<(), RPCError> {
        {
            let mut iface = self.iface.lock();
            let ip = self.server_ip.ok_or(RPCError::ClientInitializationError)?;
            let (socket, cx) = iface.get_socket_and_context::<TcpSocket>(self.server_handle);

            // TODO: add timeout?? with error returned if timeout occurs?
            socket
                .connect(cx, (ip, self.server_port), self.client_port)
                .map_err(|_| RPCError::ClientConnectError)?;
            trace!(
                "Attempting to connect to server {}:{}",
                ip,
                self.server_port
            );
        }

        // Connect to server, poll until connection is complete
        {
            loop {
                match self.iface.lock().poll(Instant::from_millis(
                    rawtime::duration_since_boot().as_millis() as i64,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("poll error: {}", e);
                    }
                }
                let mut iface = self.iface.lock();
                let socket = iface.get_socket::<TcpSocket>(self.server_handle);

                // Waiting for send/recv forces the TCP handshake to fully complete
                if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                    trace!("Connected to server, ready to send/recv data");
                    break;
                }
            }
        }
        Ok(())
    }

    fn server_accept(&self) -> Result<(), RPCError> {
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
            match self.iface.lock().poll(Instant::from_millis(
                rawtime::duration_since_boot().as_millis() as i64,
            )) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            let mut iface = self.iface.lock();
            let socket = iface.get_socket::<TcpSocket>(self.server_handle);
            if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                debug!("Connected to client!");
                break;
            }
        }
        Ok(())
    }
}
