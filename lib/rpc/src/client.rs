// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::cell::RefCell;

use log::{debug, warn};

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct Client {
    transport: Box<dyn Transport>,
    client_id: NodeId,
    req_id: u64,
    hdr: RefCell<RPCHeader>,
}

impl Client {
    pub fn new<T: 'static + Transport>(transport: Box<T>) -> Client {
        Client {
            transport,
            client_id: 0,
            req_id: 0,
            hdr: RefCell::new(RPCHeader::default()),
        }
    }
}

/// RPC client operations
impl RPCClient for Client {
    /// Registers with a RPC server
    fn connect(&mut self) -> Result<NodeId, RPCError> {
        self.transport.client_connect()?;

        // TODO: this is a dummy filler for an actual registration function
        self.call(0, 0_u8, &[], &mut []).unwrap();
        Ok(self.client_id)
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
        let data_out_len = data_out.iter().fold(0, |acc, x| acc + x.len());
        let data_in_len = data_in.iter().fold(0, |acc, x| acc + x.len());

        // Check lengths
        assert!(data_out_len + HDR_LEN <= self.transport.max_send());
        assert!(data_in_len + HDR_LEN <= self.transport.max_recv());

        // Create request header
        {
            let mut hdr = self.hdr.borrow_mut();
            hdr.pid = pid;
            hdr.req_id = self.req_id;
            hdr.msg_type = rpc_id;
            hdr.msg_len = data_in_len as u64;
        }

        // Send request header + data
        {
            let hdr = self.hdr.borrow();
            let hdr_slice = unsafe { hdr.as_bytes() };
            self.transport.send(&[hdr_slice])?;
            self.transport.send(data_in)?;
        }

        // Receive response header + data
        {
            // Receive the header
            {
                let mut hdr = self.hdr.borrow_mut();
                let hdr_slice = unsafe { hdr.as_mut_bytes() };
                self.transport.recv(&mut [hdr_slice])?;
            }

            // Read header to determine how much message data we're expecting
            let total_msg_data;
            {
                let hdr = self.hdr.borrow();
                total_msg_data = hdr.msg_len as usize;
            }
            assert!(total_msg_data <= data_out_len);

            // Fill all data
            if total_msg_data == data_out_len {
                self.transport.recv(data_out)?;

            // Partial fill
            } else {
                let mut recv_space = 0;
                let mut index = 0;
                loop {
                    if data_out[index].len() <= total_msg_data - recv_space {
                        recv_space += data_out[index].len();
                        index += 1;
                    } else {
                        break;
                    }
                }
                self.transport.recv(&mut data_out[..index])?;
                if recv_space < total_msg_data {
                    self.transport
                        .recv(&mut [&mut data_out[index][..(total_msg_data - recv_space)]])?;
                }
            }
        }

        // Check request & client IDs, and also length of received data
        let hdr = self.hdr.borrow();
        if hdr.client_id != self.client_id || hdr.req_id != self.req_id {
            warn!(
                "Mismatched client id ({}, {}) or request id ({}, {})",
                hdr.client_id, self.client_id, hdr.req_id, self.req_id
            );
            return Err(RPCError::MalformedResponse);
        }

        // Increment request id
        self.req_id += 1;

        // If registration, update id TODO: proper RPC type?
        if rpc_id == 0u8 {
            self.client_id = hdr.client_id;
            debug!("Set client ID to: {}", self.client_id);
            return Ok(());
        }
        Ok(())
    }
}
