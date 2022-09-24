// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::encode;
use alloc::boxed::Box;
use core::cell::{RefCell, UnsafeCell};

use hashbrown::HashMap;
use log::debug;

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct Server<'a> {
    transport: Box<dyn Transport + 'a>,
    handlers: RefCell<HashMap<RPCType, &'a RPCHandler>>,
    mbuf: UnsafeCell<MBuf>,
}

impl<'t, 'a> Server<'a> {
    pub fn new<T: 't + Transport>(transport: Box<T>) -> Server<'a>
    where
        't: 'a,
    {
        // Initialize the server struct
        Server {
            transport,
            handlers: RefCell::new(HashMap::new()),
            mbuf: UnsafeCell::new(MBuf {
                hdr: RPCHeader::default(),
                data: [0u8; MAX_BUFF_LEN - HDR_LEN],
            }),
        }
    }

    /// receives next RPC call with RPC ID
    fn receive(&self) -> Result<RPCType, RPCError> {
        // Receive request header
        // It is assumed the transport will only retain the mutable reference to the buffer
        // long enough to copy it into some sort of output/send buffer
        self.transport.recv_mbuf(unsafe { &mut *self.mbuf.get() })?;
        Ok(unsafe { (*self.mbuf.get()).hdr.msg_type })
    }

    /// receives next RPC call with RPC ID
    fn try_receive(&self) -> Result<Option<RPCType>, RPCError> {
        // Receive request header
        // It is assumed the transport will only retain the mutable reference to the buffer
        // long enough to copy data into it during this function call.
        if !self
            .transport
            .try_recv_mbuf(unsafe { &mut *self.mbuf.get() })?
        {
            return Ok(None);
        }

        Ok(Some(unsafe { (*self.mbuf.get()).hdr.msg_type }))
    }

    /// Replies an RPC call with results
    fn reply(&self) -> Result<(), RPCError> {
        // It is assumed the transport will only retain the mutable reference to the buffer
        // long enough to copy it into some sort of output/send buffer,
        self.transport.send_mbuf(unsafe { &mut *self.mbuf.get() })
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
    fn add_client<'c>(&mut self, func: &'c RegistrationHandler) -> Result<(), RPCError>
    where
        'c: 'a,
    {
        self.transport.server_accept()?;

        // Receive registration information
        self.receive()?;

        // TODO: registration
        // It is assumed that handler functions will only use the mutable reference to the header
        // during the function invocation (and not retain the reference), which makes it safe to
        // create a new mutable reference to the buffer during each time this function is called
        let client_id = func(unsafe { &mut (*self.mbuf.get()).hdr }, unsafe {
            &mut (*self.mbuf.get()).data
        })?;

        // Construct result
        let res = ClientIdRes { client_id };
        unsafe {
            let mut payload = &mut (*self.mbuf.get()).data;
            encode(&res, &mut (&mut payload).as_mut()).unwrap();
            let hdr = &mut (*self.mbuf.get()).hdr;
            hdr.msg_len = core::mem::size_of::<ClientIdRes>() as u64;
        }

        // Send response
        self.reply()?;
        Ok(())
    }

    /// Handle 1 RPC per client
    fn handle(&self) -> Result<(), RPCError> {
        let rpc_id = self.receive()?;
        match self.handlers.borrow().get(&rpc_id) {
            Some(func) => {
                {
                    // It is assumed that handler functions will only use the mutable reference
                    // during the function invocation (and not retain the reference), which makes it safe to
                    // create a new mutable reference to the buffer during each time this function is called
                    func(unsafe { &mut (*self.mbuf.get()).hdr }, unsafe {
                        &mut (*self.mbuf.get()).data
                    })?;
                }
                self.reply()
            }
            None => {
                debug!("Invalid RPCType({}), ignoring", rpc_id);
                Ok(())
            }
        }
    }

    /// Try to handle 1 RPC per client, if data is available (non-blocking if RPCs not available)
    fn try_handle(&self) -> Result<bool, RPCError> {
        match self.try_receive()? {
            Some(rpc_id) => match self.handlers.borrow().get(&rpc_id) {
                Some(func) => {
                    {
                        // It is assumed that handler functions will only use the mutable reference
                        // during the function invocation (and not retain the reference), which makes it safe to
                        // create a new mutable reference to the buffer during each time this function is called
                        func(unsafe { &mut (*self.mbuf.get()).hdr }, unsafe {
                            &mut (*self.mbuf.get()).data
                        })?;
                    }
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
    fn run_server(&self) -> Result<(), RPCError> {
        loop {
            let _ = self.handle()?;
        }
    }
}
