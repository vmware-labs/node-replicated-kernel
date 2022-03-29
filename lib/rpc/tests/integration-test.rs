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

        // Register an RPC handler that just returns 0, 1, 2, 3
        fn test_rpc_handler(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
            print!("In test handler\n");
            payload[0] = 0u8;
            payload[1] = 1u8;
            payload[2] = 2u8;
            payload[3] = 3u8;
            hdr.msg_len = 44;
            Ok(())
        }
        const TEST_HANDLER: RPCHandler = test_rpc_handler;
        server.register(1, &TEST_HANDLER).unwrap();

        // Register an echo RPC
        fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            print!("Registered client!\n");
            Ok(())
        }
        const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
        server.register(2, &ECHO_HANDLER).unwrap();

        // Accept a client
        fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<NodeId, RPCError> {
            print!("Registered client!\n");
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
    print!("Connected!\n");

    // Setup for RPCs
    let send_data = [1u8; 40];
    let mut recv_data = [0u8; 40];

    /*
    // Test simple test RPC
    client
        .call(0, 1, &[&send_data], &mut [&mut recv_data[..3]])
        .unwrap();
    assert_eq!([0u8, 1u8, 2u8, 3u8], recv_data[..4]);
    print!("Sent test RPC!\n");
    */

    // Test echo
    client
        .call(0, 2, &[&send_data], &mut [&mut recv_data])
        .unwrap();
    assert_eq!(send_data, recv_data);
    print!("Sent echo RPC!\n");
}
