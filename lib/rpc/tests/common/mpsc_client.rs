use std::fmt::Error;

use rpc::cluster_api::{ClusterClientAPI, ClusterError, NodeId};
use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

pub struct MPSCClient {}

impl MPSCClient {
    pub fn new() -> MPSCClient {
        MPSCClient {}
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
        Err(RPCError::NotSupported)
    }

    /// send data to a remote node
    fn msg_send(&mut self, data: Vec<u8>) -> Result<(), RPCError> {
        Err(RPCError::NotSupported)
    }

    /// receive data from a remote node
    fn msg_recv(&mut self, expected_data: usize) -> Result<Vec<u8>, RPCError> {
        Err(RPCError::NotSupported)
    }
}
