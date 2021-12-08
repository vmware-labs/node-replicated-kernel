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
    /// register an RPC func with an ID
    fn register<'c>(&self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<&Self, RPCError>
    where
        'c: 'a;

    ///  Controller-side implementation for LITE join_cluster()
    fn add_client<'c>(&self, func: &'c RegistrationHandler) -> Result<(&Self, NodeId), RPCError>
    where
        'c: 'a;

    /// Run the RPC server
    fn run_server(&self) -> Result<(), RPCError>;
}

/// RPC client operations
pub trait RPCClient {
    /// Registers with a RPC server
    fn connect(&mut self) -> Result<NodeId, RPCError>;

    /// calls a remote RPC function with ID
    fn call(
        &mut self,
        pid: usize,
        rpc_id: RPCType,
        data_in: &[u8],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError>;
}

pub trait RPCTransport {
    /// Maximum per-send payload size
    fn max_send(&self) -> usize;

    /// Maximum per-send payload size
    fn max_recv(&self) -> usize;

    /// send data to a remote node
    fn send(&self, expected_data: usize, data_buff: &[u8]) -> Result<(), RPCError>;

    /// receive data from a remote node
    fn recv(&self, expected_data: usize, data_buff: &mut [u8]) -> Result<(), RPCError>;

    /// Controller-side implementation for LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError>;

    /// Client-side implementation for LITE join_cluster()
    fn server_accept(&self) -> Result<(), RPCError>;
}
