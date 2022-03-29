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
