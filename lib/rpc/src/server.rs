// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use hashbrown::HashMap;
use log::debug;

use crate::rpc::*;
use crate::transport::Transport;

/// RPC Handler function
pub type RPCHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

/// RPC Client registration function
pub type RegistrationHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

pub struct Server<'a> {
    transport: Box<dyn Transport + Send + Sync + 'a>,
    handlers: HashMap<RPCType, &'a RPCHandler>,
    hdr: RPCHeader,
    data: [u8; 8192],
}

impl<'t, 'a> Server<'a> {
    pub fn new<T: 't + Transport + Send + Sync>(transport: Box<T>) -> Server<'a>
    where
        't: 'a,
    {
        // Initialize the server struct
        Server {
            transport,
            handlers: HashMap::new(),
            hdr: RPCHeader::default(),
            data: [0u8; 8192],
        }
    }

    /// Register an RPC func with an ID
    pub fn register<'c>(&mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        if self.handlers.contains_key(&rpc_id) {
            return Err(RPCError::DuplicateRPCType);
        }
        self.handlers.insert(rpc_id, handler);
        Ok(())
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
        match self.handlers.get(&rpc_id) {
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

    /// Try to handle 1 RPC per client, if data is available (non-blocking if RPCs not available)
    pub fn try_handle(&mut self) -> Result<bool, RPCError> {
        match self.try_receive()? {
            Some(rpc_id) => match self.handlers.get(&rpc_id) {
                Some(func) => {
                    func(&mut self.hdr, &mut self.data)?;
                    self.reply()?;
                    Ok(true)
                }
                None => {
                    debug!("Invalid RPCType({}), ignoring", rpc_id);
                    Ok(false)
                }
            },
            None => Ok(false),
        }
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
            .recv_msg(&mut self.hdr, &mut [&mut self.data])?;
        Ok(self.hdr.msg_type)
    }

    /// receives next RPC call with RPC ID
    fn try_receive(&mut self) -> Result<Option<RPCType>, RPCError> {
        // Receive request header
        if !self
            .transport
            .try_recv_msg(&mut self.hdr, &mut [&mut self.data])?
        {
            return Ok(None);
        }

        Ok(Some(self.hdr.msg_type))
    }

    /// Replies an RPC call with results
    fn reply(&mut self) -> Result<(), RPCError> {
        self.transport
            .send_msg(&self.hdr, &[&self.data[..self.hdr.msg_len as usize]])
    }
}
