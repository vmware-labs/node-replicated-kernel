// Copyright © 2023 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::sync::Once;

use smoltcp::iface::{Interface, InterfaceBuilder, NeighborCache};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

// Setup test logging.
static INIT: Once = Once::new();

fn setup_test_logging() {
    INIT.call_once(env_logger::init);
}

fn get_loopback_interface() -> Interface<'static, Loopback> {
    // from smoltcp loopback example
    let device = Loopback::new(Medium::Ethernet);
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
    let sock_vec = Vec::with_capacity(8);
    let iface = InterfaceBuilder::new(device, sock_vec)
        .hardware_addr(EthernetAddress::default().into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize();
    iface
}

#[ignore]
#[test]
fn test_client_server_shmem_transport() {
    use std::alloc::{alloc, Layout};
    use std::boxed::Box;
    use std::sync::Arc;
    use std::thread;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::{Queue, Receiver, Sender};
    use rpc::transport::ShmemTransport;

    setup_test_logging();

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

    const RPC_ECHO: RPCType = 1;

    thread::spawn(move || {
        // Create a server
        let rpc_server_transport = Box::new(server_transport);
        let mut server = Server::new(rpc_server_transport);

        // Register an echo RPC
        fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
        server.register(RPC_ECHO, &ECHO_HANDLER).unwrap();

        // Accept a client
        fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;
        server.add_client(&CLIENT_REGISTRAR).unwrap();

        // Run the server
        server.run_server(0).unwrap();
    });

    // Create a client
    let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
    let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
    let client_transport = ShmemTransport::new(client_receiver, client_sender);
    let rpc_client_transport = Box::new(client_transport);
    let mut client = Client::new(rpc_client_transport);

    // Connect to server
    client.connect(&[]).unwrap();

    // Setup for RPCs
    let send_data = [1u8; 40];
    let mut recv_data = [0u8; 40];

    // Test echo
    client
        .call(0, RPC_ECHO, &[&send_data], &mut [&mut recv_data])
        .unwrap();
    assert_eq!(send_data, recv_data);
}

#[ignore]
#[test]
fn test_client_shmem_multithread() {
    use spin::Mutex;
    use std::alloc::{alloc, Layout};
    use std::sync::Arc;
    use std::thread;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::{Queue, Receiver, Sender};
    use rpc::transport::ShmemTransport;

    setup_test_logging();

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

    const RPC_ECHO: RPCType = 1;

    thread::spawn(move || {
        // Create a server
        let rpc_server_transport = Box::new(server_transport);
        let mut server = Server::new(rpc_server_transport);

        // Register an echo RPC
        fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
        server.register(RPC_ECHO, &ECHO_HANDLER).unwrap();

        // Accept a client
        fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
            Ok(())
        }
        pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;
        server.add_client(&CLIENT_REGISTRAR).unwrap();

        // Run the server
        server.run_server(0).unwrap();
    });

    // Create a client
    let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
    let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
    let client_transport = ShmemTransport::new(client_receiver, client_sender);
    let rpc_client_transport = Box::new(client_transport);
    let client = Arc::new(Mutex::new(Client::new(rpc_client_transport)));

    {
        // Connect to server
        let my_client = Arc::clone(&client);
        my_client.lock().connect(&[]).unwrap();
    }

    for _ in 1..10 {
        let my_client = Arc::clone(&client);
        thread::spawn(move || {
            // Setup for RPCs
            let send_data = [1u8; 40];
            let mut recv_data = [0u8; 40];

            // Test echo
            my_client
                .lock()
                .call(0, RPC_ECHO, &[&send_data], &mut [&mut recv_data])
                .unwrap();
            assert_eq!(send_data, recv_data);
        });
    }
}

#[test]
fn test_client_server_tcp_transport() {
    use std::sync::Arc;
    use std::thread;

    use smoltcp::wire::IpAddress;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::tcp::interface_wrapper::InterfaceWrapper;
    use rpc::transport::TCPTransport;

    setup_test_logging();

    let iface = get_loopback_interface();

    // Create interface wrapper
    let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
    let server_iface_wrapper = interface_wrapper.clone();
    let client_iface_wrapper = interface_wrapper.clone();

    const RPC_ECHO: RPCType = 1;

    thread::scope(|s| {
        s.spawn(move || {
            // Create a server
            let rpc_server_transport =
                TCPTransport::new(None, 10111, server_iface_wrapper.clone(), 1)
                    .expect("We should be able to initialize");
            let mut server = Server::new(Box::new(rpc_server_transport));

            // Register an echo RPC
            fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
                Ok(())
            }
            const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
            server.register(RPC_ECHO, &ECHO_HANDLER).unwrap();

            // Accept a client
            fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
                Ok(())
            }
            pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;
            server.add_client(&CLIENT_REGISTRAR).unwrap();

            // Run the server
            server.handle(0).unwrap();
        });

        s.spawn(move || {
            // Create a client
            let rpc_client_transport = TCPTransport::new(
                Some((IpAddress::v4(127, 0, 0, 1), 10111)),
                10110,
                client_iface_wrapper,
                1,
            )
            .expect("We should be able to initialize");
            let mut client = Client::new(Box::new(rpc_client_transport));

            // Connect to server
            client.connect(&[]).unwrap();

            // Setup for RPCs
            let send_data = [1u8; 40];
            let mut recv_data = [0u8; 40];

            // Test echo
            client
                .call(0, RPC_ECHO, &[&send_data], &mut [&mut recv_data])
                .unwrap();
            assert_eq!(send_data, recv_data);
        });
    });
}

#[test]
fn test_client_tcp_multithread() {
    use std::sync::Arc;
    use std::thread;

    use smoltcp::wire::IpAddress;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::tcp::interface_wrapper::InterfaceWrapper;
    use rpc::transport::TCPTransport;

    setup_test_logging();

    let iface = get_loopback_interface();

    // Create interface wrapper
    let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
    let server_iface_wrapper = interface_wrapper.clone();
    let client_iface_wrapper = interface_wrapper.clone();

    const RPC_ECHO: RPCType = 1;

    // Create a client
    let rpc_client_transport = TCPTransport::new(
        Some((IpAddress::v4(127, 0, 0, 1), 10111)),
        10110,
        client_iface_wrapper,
        10,
    )
    .expect("We should be able to initialize");
    let mut client = Client::new(Box::new(rpc_client_transport));

    thread::scope(|s| {
        s.spawn(move || {
            // Create a server
            let rpc_server_transport =
                TCPTransport::new(None, 10111, server_iface_wrapper.clone(), 1)
                    .expect("We should be able to initialize");
            let mut server = Server::new(Box::new(rpc_server_transport));

            // Register an echo RPC
            fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
                Ok(())
            }
            const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
            server.register(RPC_ECHO, &ECHO_HANDLER).unwrap();

            // Accept a client
            fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
                Ok(())
            }
            pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;
            server.add_client(&CLIENT_REGISTRAR).unwrap();

            // Run the server
            for _ in 0..10 {
                server.handle(0).unwrap();
            }
        });

        // Connect to server
        client.connect(&[]).unwrap();
        let client = Arc::new(client);

        for i in 0..10 {
            let my_client = Arc::clone(&client);
            s.spawn(move || {
                // Setup for RPCs
                let send_data = [1u8; 40];
                let mut recv_data = [0u8; 40];

                // Test echo
                my_client
                    .call(i, RPC_ECHO, &[&send_data], &mut [&mut recv_data])
                    .unwrap();
                assert_eq!(send_data, recv_data);
            });
        }
    });
}

#[test]
fn test_client_server_tcp_multithread() {
    use std::sync::Arc;
    use std::thread;

    use smoltcp::wire::IpAddress;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::tcp::interface_wrapper::InterfaceWrapper;
    use rpc::transport::TCPTransport;

    setup_test_logging();

    let num_channels = 10;

    let iface = get_loopback_interface();

    // Create interface wrapper
    let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
    let server_iface_wrapper = interface_wrapper.clone();
    let client_iface_wrapper = interface_wrapper.clone();

    const RPC_ECHO: RPCType = 1;

    // Create a server
    let rpc_server_transport =
        TCPTransport::new(None, 10111, server_iface_wrapper.clone(), num_channels)
            .expect("We should be able to initialize");
    let mut server = Server::new(Box::new(rpc_server_transport));

    // Register an echo RPC
    fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
        Ok(())
    }
    const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
    server.register(RPC_ECHO, &ECHO_HANDLER).unwrap();

    // Accept a client
    fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
        Ok(())
    }
    pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;

    // Create a client
    let rpc_client_transport = TCPTransport::new(
        Some((IpAddress::v4(127, 0, 0, 1), 10111)),
        10110,
        client_iface_wrapper,
        num_channels,
    )
    .expect("We should be able to initialize");
    let mut client = Client::new(Box::new(rpc_client_transport));

    thread::scope(|s| {
        s.spawn(move || {
            server.add_client(&CLIENT_REGISTRAR).unwrap();
            let server = Arc::new(server);
            for i in 0..num_channels {
                let my_server = Arc::clone(&server);
                s.spawn(move || {
                    my_server.handle(i).unwrap();
                });
            }
        });

        client.connect(&[]).unwrap();
        let client = Arc::new(client);

        for i in 0..num_channels {
            let my_client = Arc::clone(&client);
            s.spawn(move || {
                // Setup for RPCs
                let mut send_data = [1u8; 40];
                for send_index in 0..send_data.len() {
                    send_data[send_index] = i;
                }
                let mut recv_data = [0u8; 40];

                // Test echo
                my_client
                    .call(i, RPC_ECHO, &[&send_data], &mut [&mut recv_data])
                    .unwrap();
                assert_eq!(send_data, recv_data);
            });
        }
    });
}

#[test]
fn test_multi_client_multi_server_tcp_multithread() {
    use std::sync::Arc;
    use std::thread;

    use smoltcp::wire::IpAddress;

    use rpc::client::Client;
    use rpc::rpc::{RPCError, RPCHeader, RPCType};
    use rpc::server::{RPCHandler, RegistrationHandler, Server};
    use rpc::transport::tcp::interface_wrapper::InterfaceWrapper;
    use rpc::transport::TCPTransport;

    setup_test_logging();

    let num_channels = 10;
    let num_client_server_pairs = 3;

    let iface = get_loopback_interface();

    // Create interface wrapper
    let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));

    // Define server functions
    const RPC_ECHO: RPCType = 1;
    fn echo_rpc_handler(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
        Ok(())
    }
    const ECHO_HANDLER: RPCHandler = echo_rpc_handler;
    fn register_client(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
        Ok(())
    }
    pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;

    for client_server_pair in 0..num_client_server_pairs {
        thread::scope(|s| {
            let server_iface_wrapper = interface_wrapper.clone();
            let client_iface_wrapper = interface_wrapper.clone();

            // Create a server
            let rpc_server_transport = TCPTransport::new(
                None,
                10111 + client_server_pair * 2,
                server_iface_wrapper.clone(),
                num_channels,
            )
            .expect("We should be able to initialize");
            let mut server = Server::new(Box::new(rpc_server_transport));

            server.register(RPC_ECHO, &ECHO_HANDLER).unwrap();

            // Create a client
            let rpc_client_transport = TCPTransport::new(
                Some((IpAddress::v4(127, 0, 0, 1), 10111 + client_server_pair * 2)),
                10110 + client_server_pair * 2,
                client_iface_wrapper,
                num_channels,
            )
            .expect("We should be able to initialize");
            let mut client = Client::new(Box::new(rpc_client_transport));

            s.spawn(move || {
                server.add_client(&CLIENT_REGISTRAR).unwrap();
                let server = Arc::new(server);
                for i in 0..num_channels {
                    let my_server = Arc::clone(&server);
                    s.spawn(move || {
                        my_server.handle(i).unwrap();
                    });
                }
            });

            s.spawn(move || {
                client.connect(&[]).unwrap();
                let client = Arc::new(client);

                for i in 0..num_channels {
                    let my_client = Arc::clone(&client);
                    s.spawn(move || {
                        // Setup for RPCs
                        let mut send_data = [1u8; 40];
                        for send_index in 0..send_data.len() {
                            send_data[send_index] = client_server_pair as u8;
                        }
                        let mut recv_data = [0u8; 40];

                        // Test echo
                        my_client
                            .call(i, RPC_ECHO, &[&send_data], &mut [&mut recv_data])
                            .unwrap();
                        assert_eq!(send_data, recv_data);
                    });
                }
            });
        });
    }
}
