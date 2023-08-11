// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use log::debug;

use arrayvec::ArrayVec;

use crate::rpc::*;
use crate::transport::Transport;

/// RPC Handler function
pub type RPCHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

/// RPC Client registration function
pub type RegistrationHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

pub struct Server<'a> {
    transport: Box<dyn Transport + Send + Sync + 'a>,
    handlers: ArrayVec<Option<&'a RPCHandler>, MAX_RPC_TYPE>,
    hdr: RPCHeader,
    data: [u8; 8192],
}

impl<'t, 'a> Server<'a> {
    pub fn new<T: 't + Transport + Send + Sync>(transport: Box<T>) -> Server<'a>
    where
        't: 'a,
    {
        let mut handlers = ArrayVec::new();
        for _ in 0..MAX_RPC_TYPE {
            handlers.push(None);
        }
        // Initialize the server struct
        Server {
            transport,
            handlers,
            hdr: RPCHeader::default(),
            data: [0u8; 8192],
        }
    }

    /// Register an RPC func with an ID
    pub fn register<'c>(&mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        match self.handlers[rpc_id as usize] {
            Some(_) => Err(RPCError::DuplicateRPCType),
            None => {
                self.handlers[rpc_id as usize] = Some(handler);
                Ok(())
            }
        }
    }

    /// Accept a client
    pub fn add_client<'c>(&mut self, func: &'c RegistrationHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        self.transport.server_accept()?;

        // Receive registration information
        self.receive()?;

        func(&mut self.hdr, &mut self.data)?;

        // No result for registration
        let hdr = &mut self.hdr;
        hdr.msg_len = 0;

        // Send response
        self.reply()?;
        Ok(())
    }

    /// Handle 1 RPC per client
    pub fn handle(&mut self) -> Result<(), RPCError> {
        let rpc_id = self.receive()?;
        match self.handlers[rpc_id as usize] {
            Some(func) => {
                func(&mut self.hdr, &mut self.data)?;
                self.reply()?
            }
            None => {
                return Err(RPCError::NoHandlerForRPCType);
            }
        };
        Ok(())
    }

    /// Run the RPC server
    pub fn run_server(&mut self) -> Result<(), RPCError> {
        loop {
            self.handle()?;
        }
    }

    /// receives next RPC call with RPC ID
    fn receive(&mut self) -> Result<RPCType, RPCError> {
        // Receive request header
        self.transport
            .recv_msg(&mut self.hdr, None, &mut [&mut self.data])?;
        Ok(self.hdr.msg_type)
    }

    /// Replies an RPC call with results
    fn reply(&mut self) -> Result<(), RPCError> {
        self.transport
            .send_msg(&self.hdr, &[&self.data[..self.hdr.msg_len as usize]])
    }
}
