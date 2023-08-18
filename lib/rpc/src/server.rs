// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;

use arrayvec::ArrayVec;
use spin::Mutex;

use crate::rpc::*;
use crate::transport::Transport;

/// RPC Handler function
pub type RPCHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

/// RPC Client registration function
pub type RegistrationHandler = fn(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError>;

pub struct Server<'a> {
    transport: Box<dyn Transport + Send + Sync + 'a>,
    handlers: ArrayVec<Option<&'a RPCHandler>, MAX_RPC_TYPE>,
    data: ArrayVec<Arc<Mutex<(RPCHeader, [u8; 8192])>>, MAX_INFLIGHT_MSGS>,
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

        let mut data = ArrayVec::new();
        for _ in 0..MAX_INFLIGHT_MSGS {
            data.push(Arc::new(Mutex::new((RPCHeader::default(), [0u8; 8192]))));
        }
        // Initialize the server struct
        Server {
            transport,
            handlers,
            data,
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
        // Self is mutable so id doesn't really matter, choose zero artitrarily
        let msg_id: MsgId = 0;
        let (mut hdr, mut data) = &mut *self.data[msg_id as usize].lock();

        // Receive registration information
        self.transport
            .recv_msg(&mut hdr, msg_id, &mut [&mut data])?;

        // TODO: make sure header is for right RPC type?
        func(&mut hdr, &mut data)?;

        // No result for registration
        hdr.msg_len = 0;

        // Send response
        self.transport
            .send_msg(&hdr, msg_id, &[&data[..hdr.msg_len as usize]])?;
        Ok(())
    }

    /// Handle 1 RPC per client
    pub fn handle(&self, msg_id: MsgId) -> Result<(), RPCError> {
        let (mut hdr, mut data) = &mut *self.data[msg_id as usize].lock();

        self.transport
            .recv_msg(&mut hdr, msg_id, &mut [&mut data])?;
        match self.handlers[hdr.msg_type as usize] {
            Some(func) => {
                func(&mut hdr, &mut data)?;

                // Send response
                self.transport
                    .send_msg(&hdr, msg_id, &[&data[..hdr.msg_len as usize]])?;
            }
            None => {
                return Err(RPCError::NoHandlerForRPCType);
            }
        };
        Ok(())
    }

    /// Run the RPC server
    pub fn run_server(&self, msg_id: MsgId) -> Result<(), RPCError> {
        loop {
            self.handle(msg_id)?;
        }
    }
}
