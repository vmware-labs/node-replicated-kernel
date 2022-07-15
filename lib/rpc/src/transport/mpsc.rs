// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
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
    fn max_send(&self) -> usize {
        usize::MAX
    }

    fn max_recv(&self) -> usize {
        usize::MAX
    }

    fn send(&self, send_bufs: &[&[u8]]) -> Result<(), RPCError> {
        // Calculate and check total data to receive
        let send_data_len = send_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(send_data_len <= self.max_send());

        if send_data_len == 0 {
            return Ok(());
        }

        // Copy into send buffer, so we can send it all as one message
        let mut send_vec = vec![0; send_data_len];
        let mut index = 0;
        for d in send_bufs.iter() {
            send_vec[index..(index + d.len())].copy_from_slice(&d[..]);
            index += d.len();
        }

        // Send the entire message in one go
        self.tx
            .send(send_vec)
            .map_err(|_my_err| RPCError::TransportError)?;
        Ok(())
    }

    fn try_send(&self, send_bufs: &[&[u8]]) -> Result<bool, RPCError> {
        // Calculate and check total data to receive
        let send_data_len = send_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(send_data_len <= self.max_send());

        if send_data_len == 0 {
            return Ok(true);
        }

        // Copy into send buffer, so we can send it all as one message
        let mut send_vec = vec![0; send_data_len];
        let mut index = 0;
        for d in send_bufs.iter() {
            send_vec[index..(index + d.len())].copy_from_slice(&d[..]);
            index += d.len();
        }

        // Try to send the entire message in one go
        match self.tx.try_send(send_vec) {
            Ok(_) => Ok(true),
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => Err(RPCError::TransportError),
        }
    }

    fn recv(&self, recv_bufs: &mut [&mut [u8]]) -> Result<(), RPCError> {
        // Calculate and check total data to receive
        let recv_data_len = recv_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(recv_data_len <= self.max_recv());

        if recv_data_len == 0 {
            return Ok(());
        }

        // Receive entire message in one go
        let queue_recv_buff = self.rx.recv().map_err(|_my_err| RPCError::TransportError)?;

        // Read in all msg data
        let mut data_received = 0;
        let mut index = 0;
        let mut offset = 0;
        while index < recv_bufs.len() && data_received < recv_data_len {
            let end_offset = core::cmp::min(
                recv_bufs[index].len(),
                offset + (recv_data_len - data_received),
            );

            recv_bufs[index][offset..end_offset].copy_from_slice(
                &queue_recv_buff[data_received..(data_received + (end_offset - offset))],
            );
            data_received += end_offset - offset;
            if end_offset == recv_bufs[index].len() {
                index += 1;
                offset = 0;
            } else {
                offset = end_offset;
            }
        }

        Ok(())
    }

    fn try_recv(&self, recv_bufs: &mut [&mut [u8]]) -> Result<bool, RPCError> {
        // Calculate and check total data to receive
        let recv_data_len = recv_bufs.iter().fold(0, |acc, x| acc + x.len());
        assert!(recv_data_len <= self.max_recv());

        if recv_data_len == 0 {
            return Ok(true);
        }

        // Receive some data
        return match self.rx.try_recv() {
            Ok(queue_recv_buff) => {
                // Read in all msg data
                let mut data_received = 0;
                let mut index = 0;
                let mut offset = 0;
                while index < recv_bufs.len() && data_received < recv_data_len {
                    let end_offset = core::cmp::min(
                        recv_bufs[index].len(),
                        offset + (recv_data_len - data_received),
                    );

                    recv_bufs[index][offset..end_offset].copy_from_slice(
                        &queue_recv_buff[data_received..(data_received + (end_offset - offset))],
                    );
                    data_received += end_offset - offset;
                    if end_offset == recv_bufs[index].len() {
                        index += 1;
                        offset = 0;
                    } else {
                        offset = end_offset;
                    }
                }
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(RPCError::TransportError),
        };
    }

    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError> {
        self.send(&[&unsafe { hdr.as_bytes() }[..]])?;
        self.send(payload)
    }

    fn try_send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<bool, RPCError> {
        match self.try_send(&[&unsafe { hdr.as_bytes() }[..]])? {
            true => {
                self.send(payload)?;
                Ok(true)
            }
            false => Ok(false),
        }
    }

    fn recv_msg(&self, hdr: &mut RPCHeader, payload: &mut [&mut [u8]]) -> Result<(), RPCError> {
        self.recv(&mut [&mut unsafe { hdr.as_mut_bytes() }[..]])?;
        self.recv(payload)
    }

    fn try_recv_msg(
        &self,
        hdr: &mut RPCHeader,
        payload: &mut [&mut [u8]],
    ) -> Result<bool, RPCError> {
        match self.try_recv(&mut [&mut unsafe { hdr.as_mut_bytes() }[..]])? {
            true => {
                self.recv(payload)?;
                Ok(true)
            }
            false => Ok(false),
        }
    }

    fn client_connect(&mut self) -> Result<(), RPCError> {
        // MPSC channels are already connected when transport is initialized so nothing to do here
        Ok(())
    }

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
            assert_eq!(
                true,
                server_transport
                    .try_recv(&mut [&mut server_data[0..send_data.len()]])
                    .unwrap()
            );
            assert_eq!(&send_data, &server_data[0..send_data.len()]);
            server_transport.send(&[&send_data]).unwrap();
            assert_eq!(
                false,
                server_transport
                    .try_recv(&mut [&mut server_data[0..send_data.len()]])
                    .unwrap()
            );
        });

        // In the original thread, send then receive data
        client_transport.send(&[&send_data]).unwrap();
        let mut client_data = [0u8; 1024];
        client_transport
            .recv(&mut [&mut client_data[0..send_data.len()]])
            .unwrap();
        assert_eq!(&send_data, &client_data[0..send_data.len()]);
    }
}
