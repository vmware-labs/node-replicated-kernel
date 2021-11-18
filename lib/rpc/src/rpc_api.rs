// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::result::Result;

use crate::rpc::{RPCError, RPCHeader, RPCType};

/// RPC Handler function
pub type RPCHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

/// RPC server operations
pub trait RPCServerAPI<'a> {
    /// register an RPC func with an ID
    fn register<'c>(
        &'a mut self,
        rpc_id: RPCType,
        handler: &'c RPCHandler,
    ) -> Result<&mut Self, RPCError>
    where
        'c: 'a;

    // TODO: add buff pointer as argument??
    /// receives next RPC call with RPC ID - data written to internal buffer
    fn receive(&self) -> Result<RPCType, RPCError>;

    // TODO: add buff pointer as argument??
    /// replies an RPC call with results - data sent from internal buffer
    fn reply(&self) -> Result<(), RPCError>;

    /// Run the RPC server
    fn run_server(&mut self) -> Result<(), RPCError>;
}

/// RPC client operations
pub trait RPCClientAPI {
    /// calls a remote RPC function with ID
    fn call(&mut self, pid: usize, rpc_id: RPCType, data: Vec<u8>) -> Result<Vec<u8>, RPCError>;

    /// send data to a remote node
    fn send(&self, expected_data: usize, data_buff: &mut [u8]) -> Result<(), RPCError>;

    /// receive data from a remote node
    fn recv(&self, expected_data: usize, data_buff: &mut [u8]) -> Result<(), RPCError>;
}
