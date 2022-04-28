use core::cell::UnsafeCell;

use alloc::boxed::Box;

use log::{debug, warn};

use crate::api::*;
use crate::rpc::*;
use crate::transport::Transport;

pub struct ShmemClient {
    transport: Box<dyn Transport>,
    client_id: NodeId,
    req_id: u64,
    mbuf: UnsafeCell<MBuf>,
}

impl ShmemClient {
    pub fn new<T: 'static + Transport>(transport: Box<T>) -> ShmemClient {
        ShmemClient {
            transport,
            client_id: 0,
            req_id: 0,
            mbuf: UnsafeCell::new(MBuf::default()),
        }
    }
}

impl RPCClient for ShmemClient {
    fn connect(&mut self) -> Result<NodeId, RPCError> {
        self.transport.client_connect()?;

        self.call(0, 0_u8, &[], &mut []).unwrap();
        Ok(self.client_id)
    }

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
            let mbuf = unsafe { &mut *self.mbuf.get() };
            mbuf.hdr.pid = pid;
            mbuf.hdr.req_id = self.req_id;
            mbuf.hdr.msg_type = rpc_id;
            mbuf.hdr.msg_len = data_in_len as u64;
        }

        // Send request header + data
        {
            let buf = unsafe { &mut (&mut *self.mbuf.get()).data };
            let mut copied = 0;
            for d in data_in.iter() {
                if !(*d).is_empty() {
                    buf[copied..copied + (*d).len()].copy_from_slice(*d);
                    copied += (*d).len();
                }
            }
            unsafe { self.transport.send((&*self.mbuf.get()).as_bytes())? };
        }

        // Receive response header + data
        {
            unsafe {
                self.transport
                    .recv((&mut *self.mbuf.get()).as_mut_bytes())?
            };
        }

        let hdr = unsafe { &mut (&mut *self.mbuf.get()).hdr };
        let total_msg_data = hdr.msg_len as usize;

        // Read in all msg data
        let mut copied = 0;
        let mut index = 0;
        let buf = unsafe { &mut (&mut *self.mbuf.get()).data };
        while copied < total_msg_data {
            let to_copy = total_msg_data - copied;
            let to_copy = core::cmp::min(to_copy, data_out[index].len());

            data_out[index][..to_copy].copy_from_slice(&buf[copied..copied + to_copy]);

            copied += to_copy;
            index += 1;
        }

        // Check request & client IDs, and also length of received data
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
