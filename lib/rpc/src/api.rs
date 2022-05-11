// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::result::Result;

use crate::rpc::{NodeId, RPCError, RPCHeader, RPCType};

/// RPC Handler function
pub type RPCHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

/// RPC Client registration function
pub type RegistrationHandler =
    fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<NodeId, RPCError>;

/// RPC server operations
pub trait RPCServer<'a> {
    /// Register an RPC func with an ID
    fn register<'c>(&mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
    where
        'c: 'a;

    ///  Accept an RPC client
    fn add_client<'c>(&mut self, func: &'c RegistrationHandler) -> Result<NodeId, RPCError>
    where
        'c: 'a;

    /// Run the RPC server
    fn run_server(&self) -> Result<(), RPCError>;
}

/// RPC client operations
pub trait RPCClient {
    /// Registers with a RPC server
    fn connect(&mut self) -> Result<NodeId, RPCError>;

    /// Calls a remote RPC function with ID
    fn call(
        &mut self,
        pid: usize,
        rpc_id: RPCType,
        data_in: &[&[u8]],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError>;
}
