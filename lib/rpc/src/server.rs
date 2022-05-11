// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;

use hashbrown::HashMap;
use log::debug;

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct Server<'a> {
    transport: Box<dyn Transport + 'a>,
    handlers: RefCell<HashMap<RPCType, &'a RPCHandler>>,
    hdr: RefCell<RPCHeader>,
    buff: RefCell<Vec<u8>>,
}

impl<'t, 'a> Server<'a> {
    pub fn new<T: 't + Transport>(transport: Box<T>) -> Server<'a>
    where
        't: 'a,
    {
        // Allocate space for server buffers
        let mut buff = Vec::new();
        buff.try_reserve(MAX_BUFF_LEN).unwrap();
        buff.resize(MAX_BUFF_LEN, 0);

        // Initialize the server struct
        Server {
            transport,
            handlers: RefCell::new(HashMap::new()),
            hdr: RefCell::new(RPCHeader::default()),
            buff: RefCell::new(buff),
        }
    }

    /// receives next RPC call with RPC ID
    fn receive(&self) -> Result<RPCType, RPCError> {
        // Receive request header
        {
            let mut hdr = self.hdr.borrow_mut();
            let hdr_slice = unsafe { hdr.as_mut_bytes() };
            self.transport.recv(hdr_slice)?;
        }

        {
            let hdr = self.hdr.borrow();
            let total_msg_data = hdr.msg_len as usize;
            let mut buff = self.buff.borrow_mut();
            self.transport.recv(&mut buff[..total_msg_data]).unwrap();
        }
        Ok(self.hdr.borrow().msg_type)
    }

    /// Replies an RPC call with results
    fn reply(&self) -> Result<(), RPCError> {
        // Send response header + data
        let hdr = self.hdr.borrow();
        let msg_len = hdr.msg_len as usize;
        let hdr_slice = unsafe { hdr.as_bytes() };
        self.transport.send(hdr_slice)?;

        let buff = self.buff.borrow_mut();
        self.transport.send(&buff[0..msg_len])
    }
}

/// RPC server operations
impl<'a> RPCServer<'a> for Server<'a> {
    /// Register an RPC func with an ID
    fn register<'c>(&mut self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        if self.handlers.borrow().contains_key(&rpc_id) {
            return Err(RPCError::DuplicateRPCType);
        }
        self.handlers.borrow_mut().insert(rpc_id, handler);
        Ok(())
    }

    /// Accept a client
    fn add_client<'c>(&mut self, func: &'c RegistrationHandler) -> Result<NodeId, RPCError>
    where
        'c: 'a,
    {
        self.transport.server_accept()?;

        // Receive registration information
        self.receive()?;

        // TODO: registration
        let client_id = func(&mut self.hdr.borrow_mut(), &mut self.buff.borrow_mut())?;

        // Send response
        self.reply()?;

        // Single client server, so all client IDs are 0
        Ok(client_id)
    }

    /// Run the RPC server
    fn run_server(&self) -> Result<(), RPCError> {
        loop {
            let rpc_id = self.receive()?;
            match self.handlers.borrow().get(&rpc_id) {
                Some(func) => {
                    {
                        let mut hdr = self.hdr.borrow_mut();
                        func(&mut hdr, &mut self.buff.borrow_mut())?;
                    }
                    self.reply()?;
                }
                None => debug!("Invalid RPCType({}), ignoring", rpc_id),
            }
            debug!("Finished handling RPC");
        }
    }
}
