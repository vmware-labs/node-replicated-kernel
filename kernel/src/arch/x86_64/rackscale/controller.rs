// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::boxed::Box;

use rpc::api::RPCServer;
use rpc::rpc::RPCType;

use crate::arch::debug::shutdown;
use crate::ExitReason;

use super::*;

const PORT: u16 = 6970;

/// Test TCP RPC-based controller
pub(crate) fn run() {
    let mut server: Box<dyn RPCServer> = if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        use {
            crate::transport::ethernet::init_network, rpc::server::Server,
            rpc::transport::TCPTransport,
        };
        let iface = init_network().expect("Unable to initialize vmxnet3");
        let transport =
            Box::try_new(TCPTransport::new(None, PORT, iface)).expect("Out of memory during init");
        Box::try_new(Server::new(transport)).expect("Out of memory during init")
    } else if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        use {crate::transport::shmem::create_shmem_transport, rpc::server_shmem::ShmemServer};
        let transport =
            Box::try_new(create_shmem_transport().expect("Failed to create shmem transport"))
                .expect("Out of memory during init");
        Box::try_new(ShmemServer::new(transport)).expect("Out of memory during init")
    } else {
        unreachable!("No supported transport layer specified in kernel argument");
    };

    server
        .register(LwkRpc::Close as RPCType, &CLOSE_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::Delete as RPCType, &DELETE_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::GetInfo as RPCType, &GETINFO_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::MkDir as RPCType, &MKDIR_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::Open as RPCType, &OPEN_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::FileRename as RPCType, &RENAME_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::Write as RPCType, &WRITE_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::WriteAt as RPCType, &WRITE_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::Read as RPCType, &READ_HANDLER)
        .unwrap();
    server
        .register(LwkRpc::ReadAt as RPCType, &READ_HANDLER)
        .unwrap();
    server.add_client(&CLIENT_REGISTRAR).unwrap();

    log::info!("Starting RPC server!");
    server.run_server().unwrap();

    shutdown(ExitReason::Ok);
}
