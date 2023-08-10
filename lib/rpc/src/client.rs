// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};
use spin::Mutex;

use arrayvec::ArrayVec;

use crate::rpc::*;
use crate::transport::Transport;

pub struct Client {
    transport: Arc<Mutex<Box<dyn Transport + Send + Sync>>>,
    hdrs: ArrayVec<Arc<Mutex<RPCHeader>>, MAX_INFLIGHT_MSGS>,
    msg_id: AtomicU8,
}

impl Client {
    pub fn new<T: 'static + Transport + Send + Sync>(transport: Box<T>) -> Client {
        let mut hdrs = ArrayVec::new();
        for _ in 0..MAX_INFLIGHT_MSGS {
            hdrs.push(Arc::new(Mutex::new(RPCHeader::default())));
        }
        Client {
            // Always lock transport first, then header
            transport: Arc::new(Mutex::new(transport)),
            hdrs,
            msg_id: AtomicU8::new(0),
        }
    }

    /// Registers with a RPC server
    pub fn connect(&mut self, data_in: &[&[u8]]) -> Result<(), RPCError> {
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());
        debug_assert!(data_in_len < MsgLen::MAX as usize);

        // Get client locks
        let mut transport = self.transport.lock();
        // Doesn't matter what header we use -> we are accessing the Client mutably.
        let mut hdr = self.hdrs[0].lock();

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

        // Get ourselves a message ID
        let msg_id = self.msg_id.fetch_add(1, Ordering::SeqCst);

        // Get client locks
        let transport = self.transport.lock();
        let mut hdr = self.hdrs[msg_id as usize].lock();

        // Assemble header
        hdr.msg_id = msg_id;
        hdr.msg_type = rpc_id;
        hdr.msg_len = data_in_len as MsgLen;

        // Send and receive message
        transport.send_and_recv(&mut hdr, data_in, data_out)
    }
}
