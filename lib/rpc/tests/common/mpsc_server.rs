use std::fmt::Error;

use rpc::cluster_api::{ClusterControllerAPI, ClusterError, NodeId};
use rpc::rpc::*;
use rpc::rpc_api::RPCServerAPI;

pub struct MPSCServer {}

impl MPSCServer {
    pub fn new() -> MPSCServer {
        MPSCServer {}
    }
}

impl ClusterControllerAPI for MPSCServer {
    fn add_client(&mut self) -> Result<NodeId, ClusterError> {
        Err(ClusterError::Unknown)
    }
}

impl RPCServerAPI for MPSCServer {
    /// register an RPC func with an ID
    fn rpc_register(&self, rpc_id: RPCType) -> Result<(), RPCError> {
        Err(RPCError::NotSupported)
    }

    /// receives next RPC call with RPC ID
    fn rpc_recv(&self) -> Result<(&RPCHeader, Vec<u8>), RPCError> {
        Err(RPCError::NotSupported)
    }

    /// replies an RPC call with results
    fn rpc_reply(&self, client: NodeId, data: Vec<u8>) -> Result<(), RPCError> {
        Err(RPCError::NotSupported)
    }

    /// Run the RPC server
    fn rpc_run_server(&mut self) -> Result<(), RPCError> {
        Err(RPCError::NotSupported)
    }
}
