// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::decode;
use alloc::boxed::Box;
use core::cell::UnsafeCell;

use log::{debug, error, warn};

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct Client {
    transport: Box<dyn Transport + Send>,
    client_id: ClientId,
    req_id: u64,
    hdr: UnsafeCell<RPCHeader>,
}

impl Client {
    pub fn new<T: 'static + Transport + Send>(transport: Box<T>) -> Client {
        Client {
            transport,
            client_id: 0,
            req_id: 0,
            hdr: UnsafeCell::new(RPCHeader::default()),
        }
    }
}

/// RPC client operations
impl RPCClient for Client {
    /// Registers with a RPC server
    fn connect(&mut self, data_in: &[&[u8]]) -> Result<(), RPCError> {
        self.transport.client_connect()?;

        let mut res_data = [0u8; core::mem::size_of::<ClientIdRes>()];
        self.call(0, RPC_TYPE_CONNECT, data_in, &mut [&mut res_data[..]])
            .unwrap();

        // Decode client id
        if let Some((res, _remaining)) = unsafe { decode::<ClientIdRes>(&mut res_data) } {
            let mut hdr = unsafe { &mut *self.hdr.get() };
            hdr.client_id = res.client_id;
            self.client_id = res.client_id;
            debug!("connect() - Set client_id to: {:?}", self.client_id);
        } else {
            error!("Failed to decode client id during client connection");
            return Err(RPCError::MalformedResponse);
        }
        Ok(())
    }

    /// Calls a remote RPC function with ID
    fn call(
        &mut self,
        pid: usize,
        rpc_id: RPCType,
        data_in: &[&[u8]],
        data_out: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        // Calculate total data_out len
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());

        // Create request header and send message. It is safe to create a mutable reference here
        // because it is assumed there will only be one invocation of call() running at a time, and only
        // the client has access to this field.
        let mut hdr = unsafe { &mut *self.hdr.get() };
        hdr.pid = pid;
        hdr.req_id = self.req_id;
        hdr.msg_type = rpc_id;
        hdr.msg_len = data_in_len as u64;
        self.transport.send_msg(hdr, data_in)?;

        // Receive the response
        self.transport.recv_msg(hdr, data_out)?;

        // Check request & client IDs, and also length of received data.
        if (hdr.client_id != self.client_id && rpc_id != RPC_TYPE_CONNECT)
            || hdr.req_id != self.req_id
        {
            warn!(
                "Mismatched client id ({}, {}) or request id ({}, {})",
                hdr.client_id, self.client_id, hdr.req_id, self.req_id
            );
            return Err(RPCError::MalformedResponse);
        }

        // Increment request id
        self.req_id += 1;
        Ok(())
    }
}
