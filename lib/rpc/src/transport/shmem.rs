use shmem_queue::{Sender, Receiver};

use alloc::vec::Vec;
use crate::rpc::*;
use crate::transport::Transport;

pub struct ShmemTransport<'a> {
    rx: Receiver<'a, Vec<u8>>,
    tx: Sender<'a, Vec<u8>>,
}


#[allow(dead_code)]
impl<'a> ShmemTransport<'a> {
    pub fn new(name: &str) -> ShmemTransport<'a> {
        ShmemTransport {
            rx: Receiver::new(name),
            tx: Sender::new(name)
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
            data_in[data_received..].clone_from_slice(&recv_buff[..]);
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

#[cfg(test)]
mod tests {
    #[test]
    fn shmem_tests() {
        use super::*;
        use std::thread;
        use std::sync::Arc;

        // Create transport
        let transport = Arc::new(ShmemTransport::new("queue"));
        let client_transport = transport.clone();
        let server_transport = transport.clone();

        let send_data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        thread::spawn(move || {
            // In a new server thread, receive then send data
            let mut server_data = [0u8; 1024];
            server_transport.recv(&mut server_data[0..send_data.len()])
                .unwrap();
            assert_eq!(&send_data, &server_data[0..send_data.len()]);
            server_transport.send(&send_data).unwrap();
        });

        // In the original thread, send then receive data
        client_transport.send(&send_data).unwrap();
        let mut client_data = [0u8; 1024];
        client_transport
            .recv(&mut client_data[0..send_data.len()])
            .unwrap();
        assert_eq!(&send_data, &client_data[0..send_data.len()]);
    }
}
