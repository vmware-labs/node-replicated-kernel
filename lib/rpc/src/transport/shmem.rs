use shmem_queue::{Sender, Receiver};

use alloc::vec::Vec;
use crate::rpc::*;
use crate::transport::Transport;

pub struct ShmemTransport<'a> {
    rx: Receiver<'a, Vec<u8>>,
    tx: Sender<'a, Vec<u8>>,
}

impl<'a> ShmemTransport<'a> {
    pub fn new() -> ShmemTransport<'a> {
        ShmemTransport {
            rx: Receiver::new("queue"),
            tx: Sender::new("queue")
        }
    }
}

impl<'a> Transport for ShmemTransport<'a> {
    /// Maximum per-send payload size
    fn max_send(&self) -> usize {
        usize::MAX
    }

    /// Maximum per-send payload size
    fn max_recv(&self) -> usize {
        usize::MAX
    }

    /// Send data to a remote node
    fn send(&self, data_out: &[u8]) -> Result<(), RPCError> {
        if data_out.len() == 0 {
            return Ok(());
        }

        match self.tx
            .send(data_out.to_vec()) {
                true => Ok(()),
                false => Err(RPCError::TransportError)
            }
    }

    /// Receive data from a remote node
    fn recv(&self, data_in: &mut [u8]) -> Result<(), RPCError> {
        let mut data_received = 0;

        if data_in.len() == 0 {
            return Ok(());
        }

        // Read multiple messages until expected_data has been read in
        // Assume won't ever try to receive partial messages
        while data_received < data_in.len() {
            // Receive some data
            let recv_buff = self.rx.recv();
            data_received += recv_buff.len();
        }
        Ok(())
    }

    /// Controller-side implementation for LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError> {
        Ok(())
    }

    /// Client-side implementation for LITE join_cluster()
    fn server_accept(&self) -> Result<(), RPCError> {
        Ok(())
    }
}

