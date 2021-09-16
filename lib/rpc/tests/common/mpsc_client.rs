// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode};
use std::sync::mpsc::{Receiver, SyncSender};

use rpc::cluster_api::{ClusterClientAPI, ClusterError, NodeId};
use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

pub struct MPSCClient {
    rx: Receiver<Vec<u8>>,
    tx: SyncSender<Vec<u8>>,
}

impl MPSCClient {
    pub fn new(rx: Receiver<Vec<u8>>, tx: SyncSender<Vec<u8>>) -> MPSCClient {
        MPSCClient { rx: rx, tx: tx }
    }
}

impl ClusterClientAPI for MPSCClient {
    fn join_cluster(&mut self) -> Result<NodeId, ClusterError> {
        self.call(0, RPCType::Registration, Vec::new()).unwrap();
        Ok(0) // dummy value for node ID
    }
}

/// RPC client operations
impl RPCClientAPI for MPSCClient {
    /// calls a remote RPC function with rpc_id
    fn call(&mut self, pid: usize, rpc_id: RPCType, data: Vec<u8>) -> Result<Vec<u8>, RPCError> {
        // Create request header
        let req_hdr = RPCHeader {
            client_id: 0, // dummy value, no real client ID
            pid: pid,
            req_id: 0, // dummy value, no real request ID
            msg_type: rpc_id,
            msg_len: data.len() as u64,
        };

        // Serialize request header then request body
        // We assume data is already serialized
        let mut req_data = Vec::new();
        unsafe { encode(&req_hdr, &mut req_data) }.unwrap();
        if data.len() > 0 {
            req_data.extend(data);
        }

        // send data and receive response
        self.send(req_data)?;
        let mut res_data = self.recv(0)?;

        // parse out rpc header from response data
        let (_res_hdr, payload_data) = unsafe { decode::<RPCHeader>(&mut res_data) }.unwrap();
        Ok(payload_data.to_vec())
    }

    /// send data to a remote node
    fn send(&mut self, data: Vec<u8>) -> Result<(), RPCError> {
        self.tx
            .send(data)
            .map_err(|_my_err| RPCError::TransportError)
    }

    /// receive data from a remote node
    fn recv(&mut self, _expected_data: usize) -> Result<Vec<u8>, RPCError> {
        self.rx.recv().map_err(|_my_err| RPCError::TransportError)
    }
}
