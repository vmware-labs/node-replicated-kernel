// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use fallible_collections::FallibleVecGlobal;
use hashbrown::HashMap;
use smoltcp::time::Instant;

use rpc::api::RPCServer;
use rpc::rpc::RPCType;
use rpc::server::Server;

use crate::arch::debug::shutdown;
use crate::arch::rackscale::dcm::*;
use crate::memory::backends::AllocatorStatistics;
use crate::transport::ethernet::ETHERNET_IFACE;
use crate::transport::shmem::create_shmem_manager;
use crate::ExitReason;

use super::*;

const PORT: u16 = 6970;

/// Test TCP RPC-based controller
pub(crate) fn run() {
    // Create network interface and clock
    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub(crate) struct Clock(Cell<Instant>);

    impl Clock {
        fn new() -> Clock {
            let rt = rawtime::Instant::now().as_nanos();
            let rt_millis = (rt / 1_000_000) as i64;
            Clock(Cell::new(Instant::from_millis(rt_millis)))
        }

        fn elapsed(&self) -> Instant {
            self.0.get()
        }
    }
    let clock = Clock::new();

    // Initialize the RPC server
    let workers = crate::CMDLINE.get().map_or(1, |c| c.workers);
    let mut servers: Vec<Box<dyn RPCServer>> =
        Vec::try_with_capacity(workers as usize).expect("Failed to allocate vector for RPC server");
    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        use rpc::{server::Server, transport::TCPTransport};
        let transport = Box::try_new(TCPTransport::new(None, PORT, Arc::clone(&ETHERNET_IFACE)))
            .expect("Out of memory during init");
        let mut server: Box<dyn RPCServer> =
            Box::try_new(Server::new(transport)).expect("Out of memory during init");
        register_rpcs(&mut server);
        servers.push(server);
    } else if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        use crate::transport::shmem::create_shmem_transport;
        for machine_id in 1..=workers {
            let transport = Box::try_new(
                create_shmem_transport(machine_id).expect("Failed to create shmem transport"),
            )
            .expect("Out of memory during init");
            let mut server: Box<dyn RPCServer> =
                Box::try_new(Server::new(transport)).expect("Out of memory during init");
            register_rpcs(&mut server);
            servers.push(server);
        }
    } else {
        unreachable!("No supported transport layer specified in kernel argument");
    }

    for server in servers.iter_mut() {
        server
            .add_client(&CLIENT_REGISTRAR)
            .expect("Failed to connect to remote server");
    }

    // Start running the RPC server
    log::info!("Starting RPC server!");
    loop {
        match ETHERNET_IFACE.lock().poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }

        // Try to handle an RPC request
        for server in servers.iter() {
            server.try_handle();
        }
    }

    // Shutdown
    shutdown(ExitReason::Ok);
}

fn register_rpcs(server: &mut Box<dyn RPCServer>) {
    // Register all of the RPC functions supported
    server
        .register(KernelRpc::Close as RPCType, &CLOSE_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::Delete as RPCType, &DELETE_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::GetInfo as RPCType, &GETINFO_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::MkDir as RPCType, &MKDIR_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::Open as RPCType, &OPEN_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::FileRename as RPCType, &RENAME_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::Write as RPCType, &WRITE_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::WriteAt as RPCType, &WRITE_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::Read as RPCType, &READ_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::ReadAt as RPCType, &READ_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::Log as RPCType, &LOG_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::AllocPhysical as RPCType, &ALLOC_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::RequestCore as RPCType, &CORE_HANDLER)
        .unwrap();
}
