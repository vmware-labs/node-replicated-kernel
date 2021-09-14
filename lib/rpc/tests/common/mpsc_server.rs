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
    fn rpc_register(&self, _rpc_id: RPCType) -> Result<(), RPCError> {
        // TODO
        Err(RPCError::NotSupported)
    }

    /// receives next RPC call with RPC ID
    fn rpc_recv(&self) -> Result<(&RPCHeader, Vec<u8>), RPCError> {
        let mut req_data = self.rx.recv().unwrap(); // TODO: handle error more gracefully
        return if let Some((hdr, data)) = unsafe { decode::<RPCHeader>(&mut req_data) } {
            Ok((hdr, data.to_vec()))
        } else {
            Err(RPCError::MalformedRequest)
        };
    }

    /// replies an RPC call with results
    fn rpc_reply(&self, _client: NodeId, data: Vec<u8>) -> Result<(), RPCError> {
        self.tx
            .send(data)
            .map_err(|_my_err| RPCError::TransportError)
    }

    /// Run the RPC server
    fn rpc_run_server(&mut self) -> Result<(), RPCError> {
        loop {
            let (_rpc_hdr, data) = self.rpc_recv()?;
            self.rpc_reply(0, data)?;
        }
    }
}
