// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

use crate::rpc::*;
use crate::transport::Transport;

pub struct Client {
    transport: Box<dyn Transport + Send + Sync>,
}

impl Client {
    pub fn new<T: 'static + Transport + Send + Sync>(transport: Box<T>) -> Client {
        Client { transport }
    }

    /// Registers with a RPC server
    pub fn connect(&mut self, data_in: &[&[u8]]) -> Result<(), RPCError> {
        self.transport.client_connect()?;
        let call_ret = self.call(0, RPC_TYPE_CONNECT, data_in, &mut [])?;
        if self.transport.has_response() {
            Ok(call_ret)
        } else {
            let mut hdr = RPCHeader::default();
            self.transport.recv_msg(Some(0), &mut hdr, &mut [])
        }
    }

    /// Calls a remote RPC function with ID
    /// Safety: MsgId should be unique (e.g., no other RPCs in-flight with that same MsgId)
    pub fn call(
        &self,
        msg_id: MsgId,
        rpc_id: RPCType,
        data_in: &[&[u8]],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        // Calculate total data_out len, and create header
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());
        let mut hdr = RPCHeader {
            msg_id,
            msg_type: rpc_id,
            msg_len: data_in_len as MsgLen,
        };

        // Send message.
        self.transport.send_msg(&hdr, data_in)?;

        // Receive the response
        if self.transport.has_response() {
            self.transport.recv_msg(Some(msg_id), &mut hdr, data_out)?;
        }
        Ok(())
    }
}
