use std::fmt::Error;
use std::sync::mpsc::{SyncSender, Receiver};

use rpc::cluster_api::{ClusterControllerAPI, ClusterError, NodeId};
use rpc::rpc::*;
use rpc::rpc_api::RPCServerAPI;

pub struct MPSCServer {
    rx : Receiver<Vec<u8>>,
    tx : SyncSender<Vec<u8>>,
}

impl MPSCServer {
    pub fn new(rx : Receiver<Vec<u8>>, tx : SyncSender<Vec<u8>>) -> MPSCServer {
        MPSCServer {
            rx : rx,
            tx : tx,
        }
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
        //self.rx.recv().map_err(|my_err| { RPCError::TransportError} )
        Err(RPCError::NotSupported)
    }

    /// replies an RPC call with results
    fn rpc_reply(&self, _client: NodeId, data: Vec<u8>) -> Result<(), RPCError> {
        self.tx.send(data).map_err(|my_err| { RPCError::TransportError} )
    }

    /// Run the RPC server
    fn rpc_run_server(&mut self) -> Result<(), RPCError> {
        Err(RPCError::NotSupported)
    }
}
