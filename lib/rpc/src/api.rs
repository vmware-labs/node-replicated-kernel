// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::result::Result;

use crate::rpc::{ClientId, RPCError, RPCHeader, RPCType};

/// RPC Handler function
pub type RPCHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

/// RPC Client registration function
pub type RegistrationHandler =
    fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<ClientId, RPCError>;

/// RPC server operations
pub trait RPCServer<'a> {
    /// Register an RPC func with an ID
    fn register<'c>(&mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
    where
        'c: 'a;

    /// Accept an RPC client
    fn add_client<'c>(&mut self, func: &'c RegistrationHandler) -> Result<(), RPCError>
    where
        'c: 'a;

    /// Handle 1 RPC per client
    fn handle(&self) -> Result<(), RPCError>;

    /// Try to handle 1 RPC per client, if data is available (non-blocking if RPCs not available)
    fn try_handle(&self) -> Result<bool, RPCError>;

    /// Run the RPC server
    fn run_server(&self) -> Result<(), RPCError>;
}

/// RPC client operations
pub trait RPCClient {
    /// Registers with a RPC server
    fn connect(&mut self, data_in: &[&[u8]]) -> Result<(), RPCError>;

    /// Calls a remote RPC function with ID
    fn call(
        &mut self,
        pid: usize,
        rpc_id: RPCType,
        data_in: &[&[u8]],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError>;
}
