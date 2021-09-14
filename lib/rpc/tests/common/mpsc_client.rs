use std::fmt::Error;
use std::sync::mpsc::{SyncSender, Receiver};

use rpc::cluster_api::{ClusterClientAPI, ClusterError, NodeId};
use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

pub struct MPSCClient {
    rx : Receiver<Vec<u8>>,
    tx : SyncSender<Vec<u8>>,
}

impl MPSCClient {
    pub fn new(rx : Receiver<Vec<u8>>, tx : SyncSender<Vec<u8>>) -> MPSCClient {
        MPSCClient {
            rx : rx,
            tx : tx,
        }
    }
}

impl ClusterClientAPI for MPSCClient {
    fn join_cluster(&mut self) -> Result<NodeId, ClusterError> {
        Err(ClusterError::Unknown)
    }
}

/// RPC client operations
impl RPCClientAPI for MPSCClient {
    /// calls a remote RPC function with ID
    fn rpc_call(
        &mut self,
        pid: usize,
        rpc_id: RPCType,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, RPCError> {
        // TODO create rpc header
        // TODO: concat header w/ data
        // TODO: send data with header
        self.msg_send(data)?;
        self.msg_recv(0)
    }

    /// send data to a remote node
    fn msg_send(&mut self, data: Vec<u8>) -> Result<(), RPCError> {
        self.tx.send(data).map_err(|my_err| { RPCError::TransportError} )
    }

    /// receive data from a remote node
    fn msg_recv(&mut self, _expected_data: usize) -> Result<Vec<u8>, RPCError> {
        self.rx.recv().map_err(|my_err| { RPCError::TransportError} )
    }
}
