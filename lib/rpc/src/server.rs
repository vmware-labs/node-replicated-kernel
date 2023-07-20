// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use hashbrown::HashMap;
use log::debug;

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct Server<'a> {
    transport: Box<dyn Transport + Send + Sync + 'a>,
    handlers: HashMap<RPCType, &'a RPCHandler>,
    mbuf: MBuf,
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
            mbuf: MBuf {
                hdr: RPCHeader::default(),
                data: [0u8; MAX_BUFF_LEN - HDR_LEN],
            },
        }
    }

    /// receives next RPC call with RPC ID
    fn receive(&mut self) -> Result<RPCType, RPCError> {
        // Receive request header
        self.transport.recv_mbuf(&mut self.mbuf)?;
        Ok(self.mbuf.hdr.msg_type)
    }

    /// receives next RPC call with RPC ID
    fn try_receive(&mut self) -> Result<Option<RPCType>, RPCError> {
        // Receive request header
        if !self.transport.try_recv_mbuf(&mut self.mbuf)? {
            return Ok(None);
        }

        Ok(Some(self.mbuf.hdr.msg_type))
    }

    /// Replies an RPC call with results
    fn reply(&mut self) -> Result<(), RPCError> {
        self.transport.send_mbuf(&mut self.mbuf)
    }
}

/// RPC server operations
impl<'a> RPCServer<'a> for Server<'a> {
    /// Register an RPC func with an ID
    fn register<'c>(&mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
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
    fn add_client<'c>(&mut self, func: &'c RegistrationHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        self.transport.server_accept()?;

        // Receive registration information
        self.receive()?;

        let state = func(&mut self.mbuf.hdr, &mut self.mbuf.data)?;

        // No result for registration
        let hdr = &mut self.mbuf.hdr;
        hdr.msg_len = 0;

        // Send response
        self.reply()?;
        Ok(state)
    }

    /// Handle 1 RPC per client
    fn handle(&mut self) -> Result<(), RPCError> {
        let rpc_id = self.receive()?;
        let new_state = match self.handlers.get(&rpc_id) {
            Some(func) => {
                func(&mut self.mbuf.hdr, &mut self.mbuf.data)?;
                self.reply()?
            }
            None => {
                return Err(RPCError::NoHandlerForRPCType);
            }
        };
        Ok(new_state)
    }

    /// Try to handle 1 RPC per client, if data is available (non-blocking if RPCs not available)
    fn try_handle(&mut self) -> Result<bool, RPCError> {
        match self.try_receive()? {
            Some(rpc_id) => match self.handlers.get(&rpc_id) {
                Some(func) => {
                    func(&mut self.mbuf.hdr, &mut self.mbuf.data)?;
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
    fn run_server(&mut self) -> Result<(), RPCError> {
        loop {
            self.handle()?;
        }
    }
}
