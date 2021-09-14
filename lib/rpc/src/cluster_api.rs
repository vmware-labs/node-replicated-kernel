use core::result::Result;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ClusterError {
    ServerUnreachable,
    ClientUnreachable,
    Unknown,
}

/// Node ID for servers/clients
pub type NodeId = u64;

pub trait ClusterControllerAPI {
    ///  Controller-side implementation for LITE join_cluster()
    fn add_client(&mut self) -> Result<NodeId, ClusterError>;
}

pub trait ClusterClientAPI {
    /// Register with controller, analogous to LITE join_cluster()
    fn join_cluster(&mut self) -> Result<NodeId, ClusterError>;
}
