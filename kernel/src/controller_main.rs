// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

#[cfg(feature = "shmem")]
use {crate::arch::network::create_shmem_transport, rpc::server_shmem::ShmemServer};

#[cfg(not(feature = "shmem"))]
use {crate::arch::network::init_network, rpc::server::Server, rpc::transport::TCPTransport};

use crate::arch::debug::shutdown;
use crate::arch::exokernel::*;
use rpc::rpc::RPCType;
use rpc::RPCServer;

use crate::ExitReason;

#[cfg(not(feature = "shmem"))]
const PORT: u16 = 6970;

/// Test TCP RPC-based controller
#[cfg(target_arch = "x86_64")]
pub fn run() {
    let server = {
        #[cfg(not(feature = "shmem"))]
        {
            let iface = init_network();
            let transport = Box::new(TCPTransport::new(None, PORT, iface));
            Server::new(transport)
        }
        #[cfg(feature = "shmem")]
        {
            let transport =
                Box::new(create_shmem_transport().expect("Failed to create shmem transport"));
            ShmemServer::new(transport)
        }
    };

    let (server, _) = server
        .register(FileIO::Close as RPCType, &CLOSE_HANDLER)
        .unwrap()
        .register(FileIO::Delete as RPCType, &DELETE_HANDLER)
        .unwrap()
        .register(FileIO::GetInfo as RPCType, &GETINFO_HANDLER)
        .unwrap()
        .register(FileIO::MkDir as RPCType, &MKDIR_HANDLER)
        .unwrap()
        .register(FileIO::Open as RPCType, &OPEN_HANDLER)
        .unwrap()
        .register(FileIO::FileRename as RPCType, &RENAME_HANDLER)
        .unwrap()
        .register(FileIO::Write as RPCType, &WRITE_HANDLER)
        .unwrap()
        .register(FileIO::WriteAt as RPCType, &WRITE_HANDLER)
        .unwrap()
        .register(FileIO::Read as RPCType, &READ_HANDLER)
        .unwrap()
        .register(FileIO::ReadAt as RPCType, &READ_HANDLER)
        .unwrap()
        .add_client(&CLIENT_REGISTRAR)
        .unwrap();

    log::info!("Starting RPC server!");
    server.run_server().unwrap();

    shutdown(ExitReason::Ok);
}
