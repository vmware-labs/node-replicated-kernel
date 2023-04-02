// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use fallible_collections::FallibleVecGlobal;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error, warn};
use smoltcp::time::Instant;
use spin::Mutex;
use static_assertions as sa;

use rpc::api::RPCServer;
use rpc::rpc::RPCType;
use rpc::server::Server;

use crate::arch::debug::shutdown;
use crate::arch::rackscale::dcm::*;
use crate::arch::rackscale::processops::request_core::RequestCoreReq;
use crate::cmdline::Transport;
use crate::error::KError;
use crate::memory::backends::AllocatorStatistics;
use crate::memory::mcache::MCache;
use crate::memory::LARGE_PAGE_SIZE;
use crate::nr;
use crate::process::Pid;
use crate::transport::ethernet::ETHERNET_IFACE;
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
    let num_clients = *crate::environment::NUM_MACHINES - 1;
    let mut servers: Vec<Box<dyn RPCServer<ControllerState>>> =
        Vec::try_with_capacity(num_clients as usize)
            .expect("Failed to allocate vector for RPC server");
    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        use rpc::{server::Server, transport::TCPTransport};
        let transport = Box::try_new(
            TCPTransport::new(None, PORT, Arc::clone(&ETHERNET_IFACE))
                .expect("Failed to create TCP transport"),
        )
        .expect("Out of memory during init");
        let mut server: Box<dyn RPCServer<ControllerState>> =
            Box::try_new(Server::new(transport)).expect("Out of memory during init");
        register_rpcs(&mut server);
        servers.push(server);
    } else if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        use crate::transport::shmem::create_shmem_transport;
        for machine_id in 1..=num_clients {
            let transport = Box::try_new(
                create_shmem_transport(machine_id.try_into().unwrap())
                    .expect("Failed to create shmem transport"),
            )
            .expect("Out of memory during init");
            let mut server: Box<dyn RPCServer<ControllerState>> =
                Box::try_new(Server::new(transport)).expect("Out of memory during init");
            register_rpcs(&mut server);
            servers.push(server);
        }
    } else {
        unreachable!("No supported transport layer specified in kernel argument");
    }

    let mut controller_state = ControllerState::new(num_clients as usize);

    for server in servers.iter_mut() {
        controller_state = server
            .add_client(&CLIENT_REGISTRAR, controller_state)
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
            let (mut new_state, _handled) = server
                .try_handle(controller_state)
                .expect("Controller failed to handle RPC");
            controller_state = new_state;
        }
    }

    // Shutdown
    shutdown(ExitReason::Ok);
}

fn register_rpcs(server: &mut Box<dyn RPCServer<ControllerState>>) {
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
        .register(
            KernelRpc::AllocatePhysical as RPCType,
            &ALLOCATE_PHYSICAL_HANDLER,
        )
        .unwrap();
    server
        .register(
            KernelRpc::ReleasePhysical as RPCType,
            &RELEASE_PHYSICAL_HANDLER,
        )
        .unwrap();
    server
        .register(KernelRpc::RequestCore as RPCType, &REQUEST_CORE_HANDLER)
        .unwrap();
    server
        .register(
            KernelRpc::GetHardwareThreads as RPCType,
            &GET_HARDWARE_THREADS_HANDLER,
        )
        .unwrap();
    server
        .register(
            KernelRpc::GetProcessLogs as RPCType,
            &GET_PROCESS_LOGS_HANDLER,
        )
        .unwrap();
    server
        .register(
            KernelRpc::GetShmemFrames as RPCType,
            &GET_SHMEM_FRAMES_HANDLER,
        )
        .unwrap();
    server
        .register(KernelRpc::GetWorkqueues as RPCType, &GET_WORKQUEUES_HANDLER)
        .unwrap();
    server
        .register(KernelRpc::GetNrLog as RPCType, &GET_NR_LOG_HANDLER)
        .unwrap();
}
