// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::result::Result;

use crate::rpc::RPCError;

/// Node ID for servers/clients
pub type NodeId = u64;

/// RPC Client registration function
pub type RegistrationHandler =
    fn(hdr: &mut Vec<u8>, payload: &mut Vec<u8>) -> Result<NodeId, RPCError>;

pub trait ClusterControllerAPI<'a> {
    ///  Controller-side implementation for LITE join_cluster()
    fn add_client<'c>(
        &'a mut self,
        func: &'c RegistrationHandler,
    ) -> Result<(&mut Self, NodeId), RPCError>
    where
        'c: 'a;
}

pub trait ClusterClientAPI {
    /// Register with controller, analogous to LITE join_cluster()
    fn join_cluster(&mut self) -> Result<NodeId, RPCError>;
}
