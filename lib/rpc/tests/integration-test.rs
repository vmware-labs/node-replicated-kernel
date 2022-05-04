// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[test]
fn test_client_server() {
    use std::sync::mpsc::sync_channel;
    use std::thread;

    use rpc::api::{RPCClient, RPCHandler, RPCServer, RegistrationHandler};
    use rpc::client::Client;
    use rpc::rpc::{NodeId, RPCError, RPCHeader};
    use rpc::server::Server;
    use rpc::transport::MPSCTransport;

    // Create an MPSC transport
    let (ctx, crx) = sync_channel(3);
    let (stx, srx) = sync_channel(3);

    thread::spawn(move || {
        // Create a server
        let server_transport = MPSCTransport::new(srx, ctx);
        let rpc_server_transport = Box::new(server_transport);
        let server = Server::new(rpc_server_transport);

        // Register an echo RPC
        fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
        server.register(1, &ECHO_HANDLER).unwrap();

        // Accept a client
        fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<NodeId, RPCError> {
            Ok(0)
        }
        pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;
        server.add_client(&CLIENT_REGISTRAR).unwrap();

        // Run the server
        server.run_server().unwrap();
    });

    // Create a client
    let client_transport = MPSCTransport::new(crx, stx);
    let rpc_client_transport = Box::new(client_transport);
    let mut client = Client::new(rpc_client_transport);

    // Connect to server
    client.connect().unwrap();

    // Setup for RPCs
    let send_data = [1u8; 40];
    let mut recv_data = [0u8; 40];

    // Test echo
    client
        .call(0, 1, &[&send_data], &mut [&mut recv_data])
        .unwrap();
    assert_eq!(send_data, recv_data);
}

#[test]
fn test_client_server_shmem_transport() {
    use std::alloc::{alloc, Layout};
    use std::sync::Arc;
    use std::thread;

    use rpc::api::{RPCClient, RPCHandler, RPCServer, RegistrationHandler};
    use rpc::client::Client;
    use rpc::rpc::{NodeId, PacketBuffer, RPCError, RPCHeader};
    use rpc::server::Server;
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::{Queue, Receiver, Sender};
    use rpc::transport::ShmemTransport;

    let alloc_size = 128 * 1024 * 1024;
    let alloc = (unsafe { alloc(Layout::from_size_align(alloc_size, 1).expect("Layout failed")) }
        as *mut u8) as u64;

    let allocator = ShmemAllocator::new(alloc, alloc_size as u64);
    // Create transport
    let server_to_client_queue =
        Arc::new(Queue::<PacketBuffer>::with_capacity_in(true, 32, &allocator).unwrap());
    let client_to_server_queue =
        Arc::new(Queue::<PacketBuffer>::with_capacity_in(true, 32, &allocator).unwrap());

    let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
    let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
    let server_transport = ShmemTransport::new(server_receiver, server_sender);

    thread::spawn(move || {
        // Create a server
        let rpc_server_transport = Box::new(server_transport);
        let server = Server::new(rpc_server_transport);

        // Register an echo RPC
        fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
        server.register(1, &ECHO_HANDLER).unwrap();

        // Accept a client
        fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<NodeId, RPCError> {
            Ok(0)
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

    // Connect to server
    client.connect().unwrap();

    // Setup for RPCs
    let send_data = [1u8; 40];
    let mut recv_data = [0u8; 40];

    // Test echo
    client
        .call(0, 1, &[&send_data], &mut [&mut recv_data])
        .unwrap();
    assert_eq!(send_data, recv_data);
}
