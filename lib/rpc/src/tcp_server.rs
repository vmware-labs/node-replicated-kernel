// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode};
use alloc::borrow::ToOwned;
use alloc::{vec, vec::Vec};
use hashbrown::HashMap;
use log::{debug, error, trace, warn};

use smoltcp::iface::EthernetInterface;
use smoltcp::socket::{SocketHandle, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;

use vmxnet3::smoltcp::DevQueuePhy;

use crate::cluster_api::{ClusterControllerAPI, ClusterError, NodeId};
use crate::fio_rpc::*;
use crate::rpc::*;
use crate::rpc_api::{RPCHandler, RPCServerAPI};

const RX_BUF_LEN: usize = 8192;
const TX_BUF_LEN: usize = 8192;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ServerState {
    Listening,
    Connected,
    RegistrationReceived,
    Registered,
    AwaitingResponse,
    Error,
}

pub struct TCPServer<'a> {
    iface: EthernetInterface<'a, DevQueuePhy>,
    sockets: SocketSet<'a>,
    server_handle: SocketHandle,
    state: ServerState,
    handlers: HashMap<RPCType, &'a RPCHandler>,
}

impl TCPServer<'_> {
    pub fn new<'a>(iface: EthernetInterface<'a, DevQueuePhy>, port: u16) -> TCPServer<'_> {
        let mut sockets = SocketSet::new(vec![]);
        let socket_rx_buffer = TcpSocketBuffer::new(vec![0; RX_BUF_LEN]);
        let socket_tx_buffer = TcpSocketBuffer::new(vec![0; TX_BUF_LEN]);
        let mut server_sock = TcpSocket::new(socket_rx_buffer, socket_tx_buffer);
        server_sock.listen(port).unwrap();
        debug!("Listening at port {}", port);
        let server_handle = sockets.add(server_sock);

        TCPServer {
            iface: iface,
            sockets: sockets,
            server_handle: server_handle,
            state: ServerState::Listening,
            handlers: HashMap::new(),
        }
    }
}

impl ClusterControllerAPI for TCPServer<'_> {
    fn add_client(&mut self) -> Result<NodeId, ClusterError> {
        Err(ClusterError::Unknown)
    }
}

/// RPC server operations
impl<'a> RPCServerAPI<'a> for TCPServer<'a> {
    /// register an RPC func with an ID
    fn register<'c>(&'a mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        if self.handlers.contains_key(&rpc_id) {
            return Err(RPCError::DuplicateRPCType);
        }
        self.handlers.insert(rpc_id, handler);
        Ok(())
    }

    /// receives next RPC call with RPC ID
    fn receive(&self) -> Result<(RPCHeader, Vec<u8>), RPCError> {
        Err(RPCError::NotSupported)
    }

    /// replies an RPC call with results
    fn reply(&self, _client: NodeId, _data: Vec<u8>) -> Result<(), RPCError> {
        Err(RPCError::NotSupported)
    }

    /// Run the RPC server
    fn run_server(&mut self) -> Result<(), RPCError> {
        let mut response_vec = vec![];

        loop {
            match self.iface.poll(&mut self.sockets, Instant::from_millis(0)) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            let mut socket = self.sockets.get::<TcpSocket>(self.server_handle);
            match self.state {
                ServerState::Listening => {
                    // Waiting for send/recv forces the TCP handshake to fully complete
                    // This is probably not strictly necessary on the server side
                    if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                        debug!("Connected to client!");
                        self.state = ServerState::Connected;
                    }
                }
                ServerState::Connected => {
                    if !socket.is_active() {
                        warn!("Disconnected with client before registration completed");
                        self.state = ServerState::Error;
                    }
                    if socket.can_recv() {
                        let mut data = socket
                            .recv(|buffer| {
                                let recvd_len = buffer.len();
                                let data = buffer.to_owned();
                                (recvd_len, data)
                            })
                            .unwrap();
                        if data.len() > 0 {
                            // Parse and check registration request
                            if let Some((hdr, remaining)) =
                                unsafe { decode::<RPCHeader>(&mut data) }
                            {
                                debug!("Received registration request from client: {:?}", hdr);

                                // validate request
                                if remaining.len() != 0
                                    || hdr.client_id != 0
                                    || hdr.pid != 0
                                    || hdr.req_id != 0
                                    || hdr.msg_len != 0
                                    || hdr.msg_type != FileIO::Registration as RPCType
                                {
                                    error!("Invalid registration request received, moving to error state");
                                    self.state = ServerState::Error;
                                } else {
                                    self.state = ServerState::RegistrationReceived;
                                    /*
                                    TODO: integrate better??
                                    match register_pid(hdr.pid) {
                                        Ok(_) => self.state = ServerState::RegistrationReceived,
                                        Err(err) => {
                                            error!("Could not map remote pid {} to local pid {}", hdr.pid, err);
                                            self.state = ServerState::Error;
                                        }
                                    }
                                    */
                                }
                            } else {
                                error!("Invalid data received, expected registration request, moving to error state");
                                self.state = ServerState::Error;
                            }
                        }
                    }
                }
                ServerState::RegistrationReceived => {
                    // TODO: server RPC requests
                    if !socket.is_active() {
                        error!("Client disconnected - returning to init state.");
                        self.state = ServerState::Error;
                    }
                    if socket.can_send() {
                        let res = RPCHeader {
                            client_id: 1, // TODO: used dummy client ID, need to fix.
                            pid: 0,
                            req_id: 0,
                            msg_type: FileIO::Registration as RPCType,
                            msg_len: 0,
                        };
                        let mut res_data = Vec::new();
                        unsafe { encode(&res, &mut res_data) }.unwrap();
                        socket.send_slice(&res_data).unwrap();
                        self.state = ServerState::Registered;
                    }
                }
                ServerState::Registered => {
                    if socket.can_recv() {
                        let mut data = socket
                            .recv(|buffer| {
                                let recvd_len = buffer.len();
                                let data = buffer.to_owned();
                                (recvd_len, data)
                            })
                            .unwrap();
                        if data.len() > 0 {
                            trace!(
                                "In Main, received RPC from client ({} bytes): {:?}",
                                data.len(),
                                data
                            );

                            if let Some((hdr, payload)) = unsafe { decode::<RPCHeader>(&mut data) }
                            {
                                if hdr.msg_len != payload.len() as u64 {
                                    error!("Bad payload length for request {:?}, actually found {:?} bytes, {:?}", hdr, payload.len(), payload);
                                } else {
                                    if is_fileio(hdr.msg_type) {
                                        // TODO: filler handler for now.
                                        //let res_data = handle_fileio(hdr, payload);
                                        let res = RPCHeader {
                                            client_id: 1, // TODO: used dummy client ID, need to fix.
                                            pid: hdr.pid,
                                            req_id: hdr.req_id,
                                            msg_type: FileIO::Unknown as RPCType,
                                            msg_len: 0,
                                        };
                                        let mut res_data = Vec::new();
                                        unsafe { encode(&res, &mut res_data) }.unwrap();
                                        // End filler handler

                                        trace!("Response pushed: {:?}", res_data);
                                        response_vec.push(res_data);
                                        self.state = ServerState::AwaitingResponse;
                                    } else {
                                        warn!("RPCType not implemented, ignoring: {:?}", hdr);
                                    }
                                }
                            } else {
                                warn!("Unable to parse RPC header, ignoring...");
                            }
                        }
                    }
                }
                ServerState::AwaitingResponse => {
                    if !socket.is_active() {
                        error!("Client disconnected - returning to init state.");
                        self.state = ServerState::Error;
                    }

                    if socket.can_send() && response_vec.len() > 0 {
                        if let Some(res) = response_vec.pop() {
                            socket.send_slice(&res[..]).unwrap();
                            self.state = ServerState::Registered;
                        }
                    }
                }
                ServerState::Error => {
                    // unknown error, shut down.
                    return Err(RPCError::InternalError);
                }
            }
        }
    }
}
