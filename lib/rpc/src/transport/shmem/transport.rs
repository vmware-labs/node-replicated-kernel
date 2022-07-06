use super::{Receiver, Sender};
use crate::rpc::*;
use crate::transport::Transport;

use super::queue_mpmc::QUEUE_ENTRY_SIZE;

pub struct ShmemTransport<'a> {
    rx: Receiver<'a>,
    tx: Sender<'a>,
}

#[allow(dead_code)]
impl<'a> ShmemTransport<'a> {
    pub fn new(rx: Receiver<'a>, tx: Sender<'a>) -> ShmemTransport<'a> {
        ShmemTransport { rx, tx }
    }
}

impl<'a> Transport for ShmemTransport<'a> {
    /// Maximum per-send payload size
    fn max_send(&self) -> usize {
        QUEUE_ENTRY_SIZE
    }

    /// Maximum per-send payload size
    fn max_recv(&self) -> usize {
        QUEUE_ENTRY_SIZE
    }

    /// Send data to a remote node
    fn send(&self, data_out: &[u8]) -> Result<(), RPCError> {
        if data_out.is_empty() {
            return Ok(());
        }

        match self.tx.send(data_out) {
            true => Ok(()),
            false => Err(RPCError::TransportError),
        }
    }

    fn try_recv(&self, data_in: &mut [u8]) -> Result<bool, RPCError> {
        if data_in.is_empty() {
            return Ok(true);
        }

        // TODO: how to handle didn't all fit in one entry?
        match self.rx.try_recv(data_in) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Receive data from a remote node
    fn recv(&self, data_in: &mut [u8]) -> Result<(), RPCError> {
        if data_in.is_empty() {
            return Ok(());
        }

        // TODO: how to handle didn't all fit in one entry?
        self.rx.recv(data_in);
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
    use super::*;
    use crate::transport::shmem::allocator::ShmemAllocator;
    use crate::transport::shmem::Queue;
    use std::alloc::{alloc, Layout};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn shmem_transport_test() {
        // Create transport
        let server_to_client_queue = Arc::new(Queue::new().unwrap());
        let client_to_server_queue = Arc::new(Queue::new().unwrap());

        let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
        let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
        let server_transport = Arc::new(ShmemTransport::new(server_receiver, server_sender));

        let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
        let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
        let client_transport = Arc::new(ShmemTransport::new(client_receiver, client_sender));

        let send_data = [0xa; QUEUE_ENTRY_SIZE];

        thread::spawn(move || {
            // In a new server thread, receive then send data
            let mut server_data = [0u8; QUEUE_ENTRY_SIZE];
            assert_eq!(
                true,
                server_transport
                    .try_recv(&mut server_data[0..send_data.len()])
                    .unwrap()
            );
            assert_eq!(&send_data, &server_data[0..send_data.len()]);
            server_transport.send(&send_data).unwrap();
            assert_eq!(
                false,
                server_transport
                    .try_recv(&mut server_data[0..send_data.len()])
                    .unwrap()
            );
            server_transport.send(&send_data).unwrap();
        });

        // In the original thread, send then receive data
        client_transport.send(&send_data).unwrap();
        let mut client_data = [0u8; QUEUE_ENTRY_SIZE];
        client_transport
            .recv(&mut client_data[0..send_data.len()])
            .unwrap();
        assert_eq!(&send_data, &client_data[0..send_data.len()]);
        assert_eq!(
            true,
            client_transport
                .try_recv(&mut client_data[0..send_data.len()])
                .unwrap()
        );
        assert_eq!(&send_data, &client_data[0..send_data.len()]);
    }

    #[test]
    fn shmem_transport_with_allocator_test() {
        let alloc_size = 8 * 1024 * 1024;
        let alloc =
            (unsafe { alloc(Layout::from_size_align(alloc_size, 1).expect("Layout failed")) }
                as *mut u8) as u64;

        let allocator = ShmemAllocator::new(alloc, alloc_size as u64);
        // Create transport
        let server_to_client_queue =
            Arc::new(Queue::with_capacity_in(true, 32, &allocator).unwrap());
        let client_to_server_queue =
            Arc::new(Queue::with_capacity_in(true, 32, &allocator).unwrap());

        let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
        let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
        let server_transport = Arc::new(ShmemTransport::new(server_receiver, server_sender));

        let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
        let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
        let client_transport = Arc::new(ShmemTransport::new(client_receiver, client_sender));

        let send_data = [0xa; QUEUE_ENTRY_SIZE];

        thread::spawn(move || {
            // In a new server thread, receive then send data
            let mut server_data = [0u8; QUEUE_ENTRY_SIZE];
            server_transport
                .recv(&mut server_data[0..send_data.len()])
                .unwrap();
            assert_eq!(&send_data, &server_data[0..send_data.len()]);
            server_transport.send(&send_data).unwrap();
        });

        // In the original thread, send then receive data
        client_transport.send(&send_data).unwrap();
        let mut client_data = [0u8; QUEUE_ENTRY_SIZE];
        client_transport
            .recv(&mut client_data[0..send_data.len()])
            .unwrap();
        assert_eq!(&send_data, &client_data[0..send_data.len()]);
    }
}
