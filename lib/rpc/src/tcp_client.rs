// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode};
use alloc::{vec, vec::Vec};
use log::{debug, trace, warn};

use smoltcp::iface::EthernetInterface;
use smoltcp::socket::{SocketHandle, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;

use vmxnet3::smoltcp::DevQueuePhy;

use crate::cluster_api::{ClusterClientAPI, NodeId};
use crate::rpc::*;
use crate::rpc_api::RPCClientAPI;

const RX_BUF_LEN: usize = 4096;
const TX_BUF_LEN: usize = 4096;

pub struct TCPClient<'a> {
    iface: EthernetInterface<'a, DevQueuePhy>,
    sockets: SocketSet<'a>,
    server_handle: Option<SocketHandle>,
    server_ip: IpAddress,
    server_port: u16,
    client_port: u16,
    client_id: NodeId,
    req_id: u64,
}

impl TCPClient<'_> {
    pub fn new(
        server_ip: IpAddress,
        server_port: u16,
        iface: EthernetInterface<'_, DevQueuePhy>,
    ) -> TCPClient<'_> {
        TCPClient {
            iface,
            sockets: SocketSet::new(vec![]),
            server_handle: None,
            server_ip,
            server_port,
            client_port: 10110,
            client_id: 0,
            req_id: 0,
        }
    }
}

impl ClusterClientAPI for TCPClient<'_> {
    /// Register with controller, analogous to LITE join_cluster()
    /// TODO: add timeout?? with error returned if timeout occurs?
    fn join_cluster(&mut self) -> Result<NodeId, RPCError> {
        // create client socket
        let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; RX_BUF_LEN]);
        let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; TX_BUF_LEN]);
        let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
        self.server_handle = Some(self.sockets.add(tcp_socket));

        {
            let mut socket = self.sockets.get::<TcpSocket>(self.server_handle.unwrap());
            socket
                .connect((self.server_ip, self.server_port), self.client_port)
                .unwrap();
            debug!(
                "Attempting to connect to server {}:{}",
                self.server_ip, self.server_port
            );
        }

        // Connect to server
        loop {
            match self.iface.poll(&mut self.sockets, Instant::from_millis(0)) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }
            let socket = self.sockets.get::<TcpSocket>(self.server_handle.unwrap());
            // Waiting for send/recv forces the TCP handshake to fully complete
            if socket.is_active() && (socket.may_send() || socket.may_recv()) {
                debug!("Connected to server, ready to send/recv data");
                break;
            }
        }

        // TODO: define proper type for registration??
        self.call(0, 0_u8, Vec::new()).unwrap();
        Ok(self.client_id)
    }
}

/// RPC client operations
impl RPCClientAPI for TCPClient<'_> {
    /// calls a remote RPC function with ID
    fn call(&mut self, pid: usize, rpc_id: RPCType, data: Vec<u8>) -> Result<Vec<u8>, RPCError> {
        // Create request header
        let req_hdr = RPCHeader {
            client_id: self.client_id,
            pid,
            req_id: self.req_id,
            msg_type: rpc_id,
            msg_len: data.len() as u64,
        };

        // Serialize request header then request body
        let mut req_data = Vec::new();
        unsafe { encode(&req_hdr, &mut req_data) }.unwrap();
        if !data.is_empty() {
            req_data.extend(data);
        }

        // Send request
        self.send(req_data).unwrap();

        // Receive response header
        let mut res_data = self.recv(core::mem::size_of::<RPCHeader>()).unwrap();
        let (res_hdr, extra) = unsafe { decode::<RPCHeader>(&mut res_data) }.unwrap();
        assert_eq!(extra.len(), 0);

        // Read the rest of the data
        let mut payload_data = Vec::new();
        if res_hdr.msg_len > 0 {
            payload_data = self.recv(res_hdr.msg_len as usize).unwrap();
        }

        // Check request & client IDs, and also length of received data
        if res_hdr.client_id != self.client_id || res_hdr.req_id != self.req_id {
            warn!(
                "Mismatched client id ({}, {}) or request id ({}, {})",
                res_hdr.client_id, self.client_id, res_hdr.req_id, self.req_id
            );
            return Err(RPCError::MalformedResponse);
        }

        // Increment request id
        self.req_id += 1;

        // If registration, update id TODO: proper RPC type?
        if rpc_id == 0u8 {
            self.client_id = res_hdr.client_id;
            debug!("Set client ID to: {}", self.client_id);
            return Ok(Vec::new());
        }
        Ok(payload_data)
    }

    /// send data to a remote node
    fn send(&mut self, data: Vec<u8>) -> Result<(), RPCError> {
        let mut data_sent = 0;
        loop {
            match self.iface.poll(&mut self.sockets, Instant::from_millis(0)) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            if data_sent == data.len() {
                return Ok(());
            } else {
                let mut socket = self.sockets.get::<TcpSocket>(self.server_handle.unwrap());
                if socket.can_send() && socket.send_capacity() > 0 && data_sent < data.len() {
                    let end_index = data_sent + core::cmp::min(data.len(), socket.send_capacity());
                    debug!("send [{:?}-{:?}]", data_sent, end_index);
                    if let Ok(bytes_sent) = socket.send_slice(&data[data_sent..end_index]) {
                        trace!(
                            "Client sent: [{:?}-{:?}] {:?}/{:?} bytes",
                            data_sent,
                            end_index,
                            end_index,
                            data.len()
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
    fn recv(&mut self, expected_data: usize) -> Result<Vec<u8>, RPCError> {
        let mut data = vec![0; expected_data];
        let mut total_data_received = 0;

        loop {
            match self.iface.poll(&mut self.sockets, Instant::from_millis(0)) {
                Ok(_) => {}
                Err(e) => {
                    warn!("poll error: {}", e);
                }
            }

            if total_data_received == expected_data {
                return Ok(data);
            } else {
                let mut socket = self.sockets.get::<TcpSocket>(self.server_handle.unwrap());
                if socket.can_recv() {
                    if let Ok(bytes_received) =
                        socket.recv_slice(&mut data[total_data_received..expected_data])
                    {
                        total_data_received += bytes_received;
                        trace!(
                            "rcv got {:?}/{:?} bytes",
                            total_data_received,
                            expected_data
                        );
                    } else {
                        warn!("recv_slice failed... trying again?");
                    }
                }
            }
        }
    }
}
