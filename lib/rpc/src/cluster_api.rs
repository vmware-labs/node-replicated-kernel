// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::result::Result;

use crate::rpc::{RPCHeader, RPCType};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ClusterError {
    ServerUnreachable,
    ClientUnreachable,
    Unknown,
}

/// Node ID for servers/clients
pub type NodeId = u64;

pub const CLUSTER_OPERATION: RPCType = 0;

pub fn is_reserved(rpc_id: RPCType) -> bool {
    return rpc_id == CLUSTER_OPERATION;
}

pub trait ClusterControllerAPI {
    ///  Controller-side implementation for LITE join_cluster()
    fn add_client(&mut self, hdr: RPCHeader, payload: Vec<u8>) -> Result<NodeId, ClusterError>;
}

pub trait ClusterClientAPI {
    /// Register with controller, analogous to LITE join_cluster()
    fn join_cluster(&mut self) -> Result<NodeId, ClusterError>;
}
