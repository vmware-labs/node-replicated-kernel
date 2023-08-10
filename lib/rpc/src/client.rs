// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::Mutex;

use crate::rpc::*;
use crate::transport::Transport;

pub struct Client {
    transport: Arc<Mutex<Box<dyn Transport + Send + Sync>>>,
    hdr: Arc<Mutex<RPCHeader>>,
}

impl Client {
    pub fn new<T: 'static + Transport + Send + Sync>(transport: Box<T>) -> Client {
        Client {
            // Always lock transport first, then header
            transport: Arc::new(Mutex::new(transport)),
            hdr: Arc::new(Mutex::new(RPCHeader::default())),
        }
    }

    /// Registers with a RPC server
    pub fn connect(&self, data_in: &[&[u8]]) -> Result<(), RPCError> {
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());
        debug_assert!(data_in_len < MsgLen::MAX as usize);

        // Get client locks
        let mut transport = self.transport.lock();
        let mut hdr = self.hdr.lock();

        // Connect
        transport.client_connect()?;

        // Assemble header with connection data
        hdr.msg_type = RPC_TYPE_CONNECT;
        hdr.msg_len = data_in_len as MsgLen;

        // Send and receive response
        transport.send_and_recv(&mut hdr, data_in, &mut [])
    }

    /// Calls a remote RPC function with ID
    pub fn call(
        &self,
        rpc_id: RPCType,
        data_in: &[&[u8]],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        // Calculate total data_out len
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());
        debug_assert!(data_in_len < MsgLen::MAX as usize);

        // Get client locks
        let transport = self.transport.lock();
        let mut hdr = self.hdr.lock();

        // Assemble header
        hdr.msg_type = rpc_id;
        hdr.msg_len = data_in_len as MsgLen;

        // Send and receive message
        transport.send_and_recv(&mut hdr, data_in, data_out)
    }
}
