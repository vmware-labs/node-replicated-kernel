// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::cell::RefCell;
use core::cell::UnsafeCell;

use hashbrown::HashMap;
use log::debug;

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct ShmemServer<'a> {
    transport: Box<dyn Transport + 'a>,
    handlers: RefCell<HashMap<RPCType, &'a RPCHandler>>,
    mbuf: UnsafeCell<MBuf>,
}

impl<'t, 'a> ShmemServer<'a> {
    pub fn new<T: 't + Transport>(transport: Box<T>) -> ShmemServer<'a>
    where
        't: 'a,
    {
        ShmemServer {
            transport,
            handlers: RefCell::new(HashMap::new()),
            mbuf: UnsafeCell::new(MBuf::default()),
        }
    }

    /// receives next RPC call with RPC ID
    fn receive(&self) -> Result<RPCType, RPCError> {
        let buffer = unsafe { (*self.mbuf.get()).as_mut_bytes() };
        self.transport.recv(buffer)?;
        unsafe { Ok((*self.mbuf.get()).hdr.msg_type) }
    }

    /// Replies an RPC call with results
    fn reply(&self) -> Result<(), RPCError> {
        self.transport
            .send(unsafe { (&*self.mbuf.get()).as_bytes() })
    }
}

/// RPC server operations
impl<'a> RPCServer<'a> for ShmemServer<'a> {
    /// Register an RPC func with an ID
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

    /// Accept a client
    fn add_client<'c>(&self, func: &'c RegistrationHandler) -> Result<(&Self, NodeId), RPCError>
    where
        'c: 'a,
    {
        self.transport.server_accept()?;

        // Receive registration information
        self.receive()?;

        // TODO: registration
        let client_id = unsafe { func(&mut (*self.mbuf.get()).hdr, &mut (*self.mbuf.get()).data)? };

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
                        unsafe { func(&mut (*self.mbuf.get()).hdr, &mut (*self.mbuf.get()).data)? };
                    }
                    self.reply()?;
                }
                None => debug!("Invalid RPCType({}), ignoring", rpc_id),
            }
            debug!("Finished handling RPC");
        }
    }
}
