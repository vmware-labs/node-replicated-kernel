// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(feature = "std")]
use {std::boxed::Box, std::cell::RefCell, std::vec::Vec};

#[cfg(not(feature = "std"))]
use {alloc::prelude::v1::Box, alloc::vec::Vec, core::cell::RefCell};

use hashbrown::HashMap;
use log::debug;

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

const MAX_BUFF_LEN: usize = 8192;

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
            self.transport.recv(HDR_LEN, &mut hdr_slice[..]).unwrap();
        }

        // Receive request payload
        {
            let msg_len = self.hdr.borrow().msg_len as usize;
            let mut buff = self.buff.borrow_mut();
            self.transport.recv(msg_len, &mut buff[0..msg_len]).unwrap();
        }

        Ok(self.hdr.borrow().msg_type)
    }

    /// replies an RPC call with results
    fn reply(&self) -> Result<(), RPCError> {
        // Send response header
        {
            let hdr = self.hdr.borrow();
            let hdr_slice = unsafe { hdr.as_bytes() };
            self.transport.send(HDR_LEN, &hdr_slice[..])?;
        }

        // Send response data
        {
            let msg_len = self.hdr.borrow().msg_len as usize;
            let buff = self.buff.borrow_mut();
            self.transport.send(msg_len, &buff[0..msg_len])
        }
    }
}

/// RPC server operations
impl<'a> RPCServer<'a> for Server<'a> {
    /// register an RPC func with an ID
    fn register<'c>(&self, rpc_id: RPCType, handler: &'c RPCHandler) -> Result<&Self, RPCError>
    where
        'c: 'a,
    {
        if self.handlers.borrow().contains_key(&rpc_id) {
            return Err(RPCError::DuplicateRPCType);
        }
        self.handlers.borrow_mut().insert(rpc_id, handler);
        Ok(self)
    }

    fn add_client<'c>(&self, func: &'c RegistrationHandler) -> Result<(&Self, NodeId), RPCError>
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
        Ok((self, client_id))
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