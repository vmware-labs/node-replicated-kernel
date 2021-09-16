// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode};
use std::sync::mpsc::{Receiver, SyncSender};

use rpc::cluster_api::{ClusterControllerAPI, ClusterError, NodeId};
use rpc::rpc::*;
use rpc::rpc_api::RPCServerAPI;

pub struct MPSCServer {
    rx: Receiver<Vec<u8>>,
    tx: SyncSender<Vec<u8>>,
}

impl MPSCServer {
    pub fn new(rx: Receiver<Vec<u8>>, tx: SyncSender<Vec<u8>>) -> MPSCServer {
        MPSCServer { rx: rx, tx: tx }
    }
}

impl ClusterControllerAPI for MPSCServer {
    fn add_client(&mut self) -> Result<NodeId, ClusterError> {
        Ok(0) // Dummy value for NodeID of the client
    }
}

impl RPCServerAPI for MPSCServer {
    /// register an RPC func with an ID
    fn register(&self, _rpc_id: RPCType) -> Result<(), RPCError> {
        // TODO
        Err(RPCError::NotSupported)
    }

    /// receives next RPC call with RPC ID
    fn recv(&self) -> Result<(RPCHeader, Vec<u8>), RPCError> {
        let mut req_data = self.rx.recv().unwrap(); // TODO: handle error more gracefully
        let (hdr, data) = unsafe { decode::<RPCHeader>(&mut req_data) }.unwrap();
        Ok((*hdr, data.to_vec()))
    }

    /// replies an RPC call with results
    fn reply(&self, client: NodeId, data: Vec<u8>) -> Result<(), RPCError> {
        // Create response header
        let res_hdr = RPCHeader {
            client_id: client,
            pid: 0,    // dummy value, no real client ID
            req_id: 0, // dummy value, no real request ID
            msg_type: RPCType::Unknown,
            msg_len: data.len() as u64,
        };

        // Serialize request header then request body
        // We assume data is already serialized
        let mut res_data = Vec::new();
        unsafe { encode(&res_hdr, &mut res_data) }.unwrap();
        if data.len() > 0 {
            res_data.extend(data);
        }

        // Send the data
        self.tx
            .send(res_data)
            .map_err(|_my_err| RPCError::TransportError)
    }

    /// Run the RPC server
    fn run_server(&mut self) -> Result<(), RPCError> {
        loop {
            let (_rpc_hdr, data) = self.recv()?;
            self.reply(0, data)?;
        }
    }
}
