// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

use crate::rpc::*;
use crate::transport::Transport;

pub struct Client {
    transport: Box<dyn Transport + Send + Sync>,
    hdr: RPCHeader,
}

impl Client {
    pub fn new<T: 'static + Transport + Send + Sync>(transport: Box<T>) -> Client {
        Client {
            transport,
            hdr: RPCHeader::default(),
        }
    }

    /// Registers with a RPC server
    pub fn connect(&mut self, data_in: &[&[u8]]) -> Result<(), RPCError> {
        self.transport.client_connect()?;
        self.call(RPC_TYPE_CONNECT, data_in, &mut [])
    }

    /// Calls a remote RPC function with ID
    pub fn call(
        &mut self,
        rpc_id: RPCType,
        data_in: &[&[u8]],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        // Calculate total data_out len
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());
        debug_assert!(data_in_len < MsgLen::MAX as usize);

        // Create request header and send message. It is safe to create a mutable reference here
        // because it is assumed there will only be one invocation of call() running at a time, and only
        // the client has access to this field.
        let mut hdr = &mut self.hdr;
        hdr.msg_type = rpc_id;
        hdr.msg_len = data_in_len as MsgLen;
        self.transport.send_msg(hdr, data_in)?;

        // Receive the response
        self.transport.recv_msg(hdr, data_out)?;
        Ok(())
    }
}
