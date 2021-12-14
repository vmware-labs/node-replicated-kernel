// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::mpsc::{Receiver, SyncSender};

use crate::rpc::*;
use crate::transport::Transport;

pub struct MPSCTransport {
    rx: Receiver<Vec<u8>>,
    tx: SyncSender<Vec<u8>>,
}

impl MPSCTransport {
    pub fn new(rx: Receiver<Vec<u8>>, tx: SyncSender<Vec<u8>>) -> MPSCTransport {
        MPSCTransport { rx: rx, tx: tx }
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

    /// send data to a remote node
    fn send(&self, expected_data: usize, data_buff: &[u8]) -> Result<(), RPCError> {
        self.tx
            .send(data_buff[..expected_data].to_vec())
            .map_err(|_my_err| RPCError::TransportError)
    }

    /// receive data from a remote node
    fn recv(&self, expected_data: usize, data_buff: &mut [u8]) -> Result<(), RPCError> {
        let mut data_received = 0;

        // Read multiple messages until expected_data has been read in
        // Assume messages haven't been stuck together e.g. will always read an entire message
        while data_received < expected_data {
            let mut recv_buff = self.rx.recv().map_err(|_my_err| RPCError::TransportError)?;
            data_buff[data_received..(data_received + recv_buff.len())]
                .clone_from_slice(&mut recv_buff);
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
    fn transport_init() {
        use std::sync::mpsc::sync_channel;
        use std::thread;

        use crate::transport::MPSCTransport;
        use crate::transport::Transport;

        let (ctx, crx) = sync_channel(3);
        let (stx, srx) = sync_channel(3);
        let client_transport = MPSCTransport::new(crx, stx);
        let server_transport = MPSCTransport::new(srx, ctx);

        let send_data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        thread::spawn(move || {
            let mut server_data = [0u8; 1024];
            server_transport
                .recv(send_data.len(), &mut server_data)
                .unwrap();
            assert_eq!(&send_data, &server_data[..send_data.len()]);
            server_transport.send(send_data.len(), &send_data).unwrap();
        });

        client_transport.send(send_data.len(), &send_data).unwrap();
        let mut client_data = [0u8; 1024];
        client_transport
            .recv(send_data.len(), &mut client_data)
            .unwrap();
        assert_eq!(&send_data, &client_data[..send_data.len()]);
    }
}
