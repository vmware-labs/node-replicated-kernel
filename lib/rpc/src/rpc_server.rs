// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::cell::RefCell;
use hashbrown::HashMap;
use log::{debug, trace, warn};

use smoltcp::iface::EthernetInterface;
use smoltcp::socket::{SocketHandle, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;

use vmxnet3::smoltcp::DevQueuePhy;

use crate::rpc::*;
use crate::rpc_api::{RPCHandler, RPCServer, RegistrationHandler};

const RX_BUF_LEN: usize = 8192;
const TX_BUF_LEN: usize = 8192;
const BUF_LEN: usize = 8192;

pub struct DefaultRPCServer<'a> {
    iface: RefCell<EthernetInterface<'a, DevQueuePhy>>,
    sockets: RefCell<SocketSet<'a>>,
    server_handle: SocketHandle,
    handlers: RefCell<HashMap<RPCType, &'a RPCHandler>>,
    hdr: RefCell<RPCHeader>,
    buff: RefCell<Vec<u8>>,
}

impl DefaultRPCServer<'_> {
    pub fn new(iface: EthernetInterface<'_, DevQueuePhy>, port: u16) -> DefaultRPCServer<'_> {
        // Allocate space for server buffers
        let mut buff = Vec::new();
        buff.try_reserve(BUF_LEN).unwrap();
        buff.resize(BUF_LEN, 0);

        // Create SocketSet w/ space for 1 socket
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(1).unwrap();
        let mut sockets = SocketSet::new(sock_vec);

        // Create RX and TX buffers for the socket
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(RX_BUF_LEN).unwrap();
        sock_vec.resize(RX_BUF_LEN, 0);
        let socket_rx_buffer = TcpSocketBuffer::new(sock_vec);
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(TX_BUF_LEN).unwrap();
        sock_vec.resize(TX_BUF_LEN, 0);
        let socket_tx_buffer = TcpSocketBuffer::new(sock_vec);

        // Initialized the socket and begin listening
        let mut server_sock = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);
        server_sock.listen(port).unwrap();
        debug!("Listening at port {}", port);

        // Add socket to socket set
        let server_handle = sockets.add(server_sock);

        // Initialize the server struct
        DefaultRPCServer {
            iface: RefCell::new(iface),
            sockets: RefCell::new(sockets),
            server_handle,
            handlers: RefCell::new(HashMap::new()),
            hdr: RefCell::new(RPCHeader::default()),
            buff: RefCell::new(buff),
        }
    }

    fn recv(&self, is_hdr: bool, expected_data: usize) -> Result<(), RPCError> {
        let mut total_data_received = 0;

        // Check write size - make sure it fits in buffer
        if is_hdr {
            assert!(expected_data == HDR_LEN);
        } else {
            assert!(expected_data <= self.buff.borrow().len());
        }

        // Chunked receive into internal buffer
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

            // Check if done
            if total_data_received == expected_data {
                return Ok(());

            // If not done, attempt to receive slice containing remaining data
            } else {
                let mut socket = sockets.get::<TcpSocket>(self.server_handle);
                if socket.can_recv() {
                    // Write slice into hdr (for RPC Header) or buff (for RPC data)
                    let result = if is_hdr {
                        {
                            let mut hdr = self.hdr.borrow_mut();
                            let hdr_slice = unsafe { hdr.as_mut_bytes() };
                            socket.recv_slice(&mut hdr_slice[..])
                        }
                    } else {
                        socket.recv_slice(
                            &mut self.buff.borrow_mut()[total_data_received..expected_data],
                        )
                    };

                    // Update total data received
                    if let Ok(bytes_received) = result {
                        total_data_received += bytes_received;
                        debug!(
                            "rcv got {:?}/{:?} bytes",
                            total_data_received, expected_data
                        );

                    // Ignore failures
                    } else {
                        warn!("recv_slice failed... trying again?");
                    }
                }
            }
        }
    }

    fn send(&self, is_hdr: bool, expected_data: usize) -> Result<(), RPCError> {
        let mut data_sent = 0;

        // Check send size - make sure send is within buffer bounds
        if is_hdr {
            assert!(expected_data == HDR_LEN);
        } else {
            assert!(expected_data <= self.buff.borrow().len());
        }

        // Chunked send from internal buffer
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

            // Check if done
            if data_sent == expected_data {
                return Ok(());

            // If not done, send more data
            } else {
                // Only send as much as space in socket.send_capacity
                let mut socket = sockets.get::<TcpSocket>(self.server_handle);
                if socket.can_send() && socket.send_capacity() > 0 && data_sent < expected_data {
                    let end_index = data_sent
                        + core::cmp::min(expected_data - data_sent, socket.send_capacity());
                    // Send in hdr (for RPCHeader) or buff (for RPC data)
                    let result = if is_hdr {
                        {
                            let hdr = self.hdr.borrow();
                            let hdr_slice = unsafe { hdr.as_bytes() };
                            let ret = socket.send_slice(&hdr_slice[..]);
                            debug!(
                                "sent: [{:?}-{:?}] {:?}/{:?} bytes",
                                data_sent, end_index, end_index, expected_data
                            );
                            ret
                        }
                    } else {
                        let ret = socket.send_slice(&self.buff.borrow()[data_sent..end_index]);
                        debug!(
                            "sent: [{:?}-{:?}] {:?}/{:?} bytes",
                            data_sent, end_index, end_index, expected_data
                        );
                        ret
                    };

                    // Log and update total
                    if let Ok(bytes_sent) = result {
                        trace!(
                            "sent: [{:?}-{:?}] {:?}/{:?} bytes",
                            data_sent,
                            end_index,
                            end_index,
                            expected_data
                        );
                        data_sent += bytes_sent;

                    // Ignore failures
                    } else {
                        debug!("send_slice failed... trying again?");
                    }
                }
            }
        }
    }
}

/// RPC server operations
impl<'a> RPCServer<'a> for DefaultRPCServer<'a> {
    /// register an RPC func with an ID
    fn register<'c>(
        &'a mut self,
        rpc_id: RPCType,
        handler: &'c RPCHandler,
    ) -> Result<&mut Self, RPCError>
    where
        'c: 'a,
    {
        if self.handlers.borrow().contains_key(&rpc_id) {
            return Err(RPCError::DuplicateRPCType);
        }
        self.handlers.borrow_mut().insert(rpc_id, handler);
        Ok(self)
    }

    /// receives next RPC call with RPC ID
    fn receive(&self) -> Result<RPCType, RPCError> {
        // Read header into internal buffer
        self.recv(true, HDR_LEN)?;

        // Receive the rest of the data
        self.recv(false, self.hdr.borrow().msg_len as usize)?;
        Ok(self.hdr.borrow().msg_type)
    }

    /// replies an RPC call with results
    fn reply(&self) -> Result<(), RPCError> {
        // Send header from internal buffer
        self.send(true, HDR_LEN)?;

        // Send the rest of the data
        self.send(false, self.hdr.borrow().msg_len as usize)
    }

    /// Run the RPC server
    fn run_server(&mut self) -> Result<(), RPCError> {
        loop {
            let rpc_id = self.receive()?;
            match self.handlers.borrow().get(&rpc_id) {
                Some(func) => {
                    {
                        let mut hdr = self.hdr.borrow_mut();
                        func(&mut hdr, &mut self.buff.borrow_mut())?;
                    }
                    self.reply()?;
                }
                None => debug!("Invalid RPCType({}), ignoring", rpc_id),
            }
            debug!("Finished handling RPC");
        }
    }

    fn add_client<'c>(
        &'a mut self,
        func: &'c RegistrationHandler,
    ) -> Result<(&mut Self, NodeId), RPCError>
    where
        'c: 'a,
    {
        // Receive registration information
        self.receive()?;

        // Run specified registration function
        let client_id = func(&mut self.hdr.borrow_mut(), &mut self.buff.borrow_mut())?;

        // Send response
        self.reply()?;

        // Single client server, so all client IDs are 0
        Ok((self, client_id))
    }
}
