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
            let mut pointers: [&[u8]; 7] = [&[1]; 7];
            pointers[0] = unsafe { &((*self.mbuf.get()).hdr).as_bytes()[..] };
            let mut index = 1;
            for d in data_in {
                pointers[index] = d;
                index += 1;
            }
            unsafe {
                self.transport.send(&pointers[..data_in.len() + 1])?;
            }
        }

        // Receive response header + data
        {
            let mut pointers: [&mut [u8]; 7] = [
                &mut [1],
                &mut [1],
                &mut [1],
                &mut [1],
                &mut [1],
                &mut [1],
                &mut [1],
            ];
            pointers[0] = unsafe { &mut ((*self.mbuf.get()).hdr).as_mut_bytes()[..] };
            let mut index = 1;
            let num_out = data_out.len() + 1;
            for d in data_out {
                pointers[index] = d;
                index += 1;
            }
            unsafe {
                self.transport.recv(&mut pointers[..num_out])?;
            };
        }

        let hdr = unsafe { &mut (*self.mbuf.get()).hdr };

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
