// Copyright © 2023 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[test]
fn test_shmem_multithread() {
    shmem_multithread(10)
}

#[test]
fn test_shmem_singlethread() {
    shmem_multithread(10)
}

fn shmem_multithread(num_clients: u8) {
    use spin::Mutex;
    use std::alloc::{alloc, Layout};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time;

    use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
    use core2::io::Result as IOResult;
    use core2::io::Write;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::{Queue, Receiver, Sender};
    use rpc::transport::ShmemTransport;

    let alloc_size = 128 * 1024 * 1024;
    let alloc = (unsafe { alloc(Layout::from_size_align(alloc_size, 1).expect("Layout failed")) }
        as *mut u8) as u64;

    let allocator = ShmemAllocator::new(alloc, alloc_size as u64);
    // Create transport
    let server_to_client_queue = Arc::new(Queue::with_capacity_in(true, 32, &allocator).unwrap());
    let client_to_server_queue = Arc::new(Queue::with_capacity_in(true, 32, &allocator).unwrap());

    let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
    let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
    let server_transport = ShmemTransport::new(server_receiver, server_sender);

    const RPC_INC: RPCType = 1;
    struct RPCIncStruct {
        response_buffer: usize,
        response_done: usize,
    }
    unsafe_abomonate!(RPCIncStruct: response_buffer, response_done);

    thread::spawn(move || {
        // Create a server
        let rpc_server_transport = Box::new(server_transport);
        let mut server = Server::new(rpc_server_transport);

        // Register an echo RPC
        fn inc_rpc_handler(_hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
            if let Some((req, _)) = unsafe { decode::<RPCIncStruct>(payload) } {
                let mut buff_arc = unsafe { Arc::from_raw(req.response_buffer as *const [u8; 40]) };
                let done = unsafe { Arc::from_raw(req.response_done as *const AtomicBool) };
                let buff = Arc::get_mut(&mut buff_arc).unwrap();
                for i in 0..40 {
                    buff[i] += 1;
                }
                done.store(true, Ordering::SeqCst);
                Ok(())
            // Report error if failed to decode request
            } else {
                Err(RPCError::MalformedRequest)
            }
        }
        const INC_HANDLER: RPCHandler = inc_rpc_handler;
        server.register(RPC_INC, &INC_HANDLER).unwrap();

        // Accept a client
        fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;
        server.add_client(&CLIENT_REGISTRAR).unwrap();

        // Run the server
        server.run_server().unwrap();
    });

    // Create a client
    let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
    let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
    let client_transport = ShmemTransport::new(client_receiver, client_sender);
    let rpc_client_transport = Box::new(client_transport);
    let mut client = Client::new(rpc_client_transport);
    client.connect(&[]).unwrap();

    let client_arc = Arc::new(client);

    for i in 1..num_clients {
        let my_client = Arc::clone(&client_arc);
        let id = i;
        thread::spawn(move || {
            // Setup for RPCs
            let response_buffer = Arc::new([0u8; 40]).clone();
            let response_done = Arc::new(AtomicBool::new(false));

            let my_struct = RPCIncStruct {
                response_buffer: (*&Arc::into_raw(response_buffer.clone()) as *const [u8; 40])
                    as usize,
                response_done: (*&Arc::into_raw(response_done.clone()) as *const AtomicBool)
                    as usize,
            };

            let mut send_data = [0u8; core::mem::size_of::<RPCIncStruct>()];
            unsafe { encode(&my_struct, &mut (&mut send_data).as_mut()) }
                .expect("Failed to encode inc struct");

            my_client.call(id, RPC_INC, &[&send_data], &mut []).unwrap();

            while !response_done.load(Ordering::SeqCst) {
                thread::sleep(time::Duration::from_millis(10));
            }

            for i in 0..response_buffer.len() {
                assert_eq!(response_buffer[i], 1u8);
            }
        });
    }
}
