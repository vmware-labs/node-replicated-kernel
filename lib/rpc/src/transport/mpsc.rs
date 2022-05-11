// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::mpsc::{Receiver, SyncSender};
use std::vec::Vec;

use crate::rpc::*;
use crate::transport::Transport;

pub struct MPSCTransport {
    rx: Receiver<Vec<u8>>,
    tx: SyncSender<Vec<u8>>,
}

impl MPSCTransport {
    pub fn new(rx: Receiver<Vec<u8>>, tx: SyncSender<Vec<u8>>) -> MPSCTransport {
        MPSCTransport { rx, tx }
    }
}

/// RPC client operations
impl Transport for MPSCTransport {
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
        if data_out.is_empty() {
            return Ok(());
        }

        self.tx
            .send(data_out.to_vec())
            .map_err(|_my_err| RPCError::TransportError)
    }

    /// Receive data from a remote node
    fn recv(&self, data_in: &mut [u8]) -> Result<(), RPCError> {
        let mut data_received = 0;

        if data_in.is_empty() {
            return Ok(());
        }

        // Read multiple messages until expected_data has been read in
        // Assume won't ever try to receive partial messages
        while data_received < data_in.len() {
            // Receive some data
            let recv_buff = self.rx.recv().map_err(|_my_err| RPCError::TransportError)?;
            data_in[data_received..].clone_from_slice(&recv_buff[..]);
            data_received += recv_buff.len();
        }
        Ok(())
    }

    /// Controller-side implementation for LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError> {
        // MPSC channels are already connected when transport is initialized so nothing to do here
        Ok(())
    }

    /// Client-side implementation for LITE join_cluster()
    fn server_accept(&self) -> Result<(), RPCError> {
        // MPSC channels are already connected when transport is initialized so nothing to do here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mpsc_tests() {
        use super::*;
        use std::sync::mpsc::sync_channel;
        use std::thread;

        // Create transports
        let (ctx, crx) = sync_channel(3);
        let (stx, srx) = sync_channel(3);
        let client_transport = MPSCTransport::new(crx, stx);
        let server_transport = MPSCTransport::new(srx, ctx);

        let send_data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        thread::spawn(move || {
            // In a new server thread, receive then send data
            let mut server_data = [0u8; 1024];
            server_transport
                .recv(&mut server_data[0..send_data.len()])
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
