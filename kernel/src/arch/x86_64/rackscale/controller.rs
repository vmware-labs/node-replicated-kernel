// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::Cell;
use hashbrown::HashMap;
use smoltcp::time::Instant;

use rpc::api::RPCServer;
use rpc::rpc::RPCType;
use rpc::server::Server;
use rpc::transport::Transport as RPCTransport;

use crate::arch::debug::shutdown;
use crate::arch::rackscale::dcm::*;
use crate::transport::ethernet::init_network;
use crate::ExitReason;

use super::*;

const PORT: u16 = 6970;

/// Test TCP RPC-based controller
pub(crate) fn run() {
    // Create network interface and clock
    let iface = init_network().expect("Failed to initialize network interface");
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

    // Initialize DCM
    let dcmController = DCMInterface::new(Arc::clone(&iface));

    // Initialize the RPC server
    let mut server: Box<dyn RPCServer> = if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        use rpc::{server::Server, transport::TCPTransport};
        let transport = Box::try_new(TCPTransport::new(None, PORT, Arc::clone(&iface)))
            .expect("Out of memory during init");
        Box::try_new(Server::new(transport)).expect("Out of memory during init")
    } else if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        use crate::transport::shmem::create_shmem_transport;
        let transport =
            Box::try_new(create_shmem_transport().expect("Failed to create shmem transport"))
                .expect("Out of memory during init");
        Box::try_new(Server::new(transport)).expect("Out of memory during init")
    } else {
        unreachable!("No supported transport layer specified in kernel argument");
    };

    register_rpcs(&mut server);

    // Start running the RPC server
    log::info!("Starting RPC server!");
    loop {
        match iface.borrow_mut().poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }

        // Try to handle an RPC request
        let _ = server.try_handle().unwrap();

        // Check DCM UDP messages
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
    server.add_client(&CLIENT_REGISTRAR).unwrap();
}
