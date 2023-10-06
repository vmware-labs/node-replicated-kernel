// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use arrayvec::ArrayVec;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use smoltcp::time::Instant;

use rpc::rpc::RPCType;
use rpc::server::Server;
use rpc::transport::TCPTransport;

use crate::arch::rackscale::dcm::{
    DCMOps, DCM_CLIENT_REGISTRAR, DCM_SERVER_PORT, NODE_ASSIGNMENT_HANDLER,
};
use crate::arch::MAX_MACHINES;
use crate::cmdline::Transport;
use crate::transport::ethernet::ETHERNET_IFACE;
use crate::transport::shmem::create_shmem_transport;

use super::*;

pub(crate) const CONTROLLER_PORT_BASE: u16 = 6970;

static ClientReadyCount: AtomicU64 = AtomicU64::new(0);
static DCMServerReady: AtomicBool = AtomicBool::new(false);

/// Controller main method
pub(crate) fn run() {
    let mid = *crate::environment::CORE_ID;

    // Initialize one server per controller thread
    let mut server = if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        let transport = Box::new(
            TCPTransport::new(
                None,
                CONTROLLER_PORT_BASE + mid as u16 - 1,
                Arc::clone(&ETHERNET_IFACE),
            )
            .expect("Failed to create TCP transport"),
        );
        let mut server = Server::new(transport);
        register_rpcs(&mut server);
        server
    } else if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        let transport = Box::new(
            create_shmem_transport(mid.try_into().unwrap())
                .expect("Failed to create shmem transport"),
        );

        let mut server = Server::new(transport);
        register_rpcs(&mut server);
        server
    } else {
        unreachable!("No supported transport layer specified in kernel argument");
    };

    ClientReadyCount.fetch_add(1, Ordering::SeqCst);

    // Wait for all clients to connect before fulfilling any RPCs.
    while !DCMServerReady.load(Ordering::SeqCst) {}

    server
        .add_client(&CLIENT_REGISTRAR)
        .expect("Failed to accept client");

    ClientReadyCount.fetch_add(1, Ordering::SeqCst);

    // Wait for all clients to connect before fulfilling any RPCs.
    while ClientReadyCount.load(Ordering::SeqCst) != (*crate::environment::NUM_MACHINES - 1) as u64
    {
    }

    #[cfg(feature = "test-controller-shmem-alloc")]
    {
        if mid == 1 {
            // We don't put this in integration.rs because it must happen midway-through controller initialization
            use crate::arch::debug::shutdown;
            use crate::arch::rackscale::dcm::affinity_alloc::dcm_affinity_alloc;
            use crate::memory::shmem_affinity::mid_to_shmem_affinity;
            use crate::transport::shmem::SHMEM;
            use crate::ExitReason;

            let LARGE_PAGES_PER_CLIENT = 2;
            let num_clients = *crate::environment::NUM_MACHINES - 1;

            for test_mid in 1..(num_clients + 1) {
                let regions = dcm_affinity_alloc(test_mid, LARGE_PAGES_PER_CLIENT)
                    .expect("Controller failed to allocate!");
                assert!(regions.len() == LARGE_PAGES_PER_CLIENT);
                for i in 0..LARGE_PAGES_PER_CLIENT {
                    assert!(
                        regions[i].base >= SHMEM.devices[test_mid].region.base.as_u64()
                            && regions[i].base
                                < SHMEM.devices[test_mid].region.base.as_u64()
                                    + SHMEM.devices[test_mid].region.size as u64
                    );
                    assert!(regions[i].affinity == mid_to_shmem_affinity(test_mid));
                }
            }
            log::info!("controller_shmem_alloc OK");
            shutdown(ExitReason::Ok);
        }
    }

    // Start running the RPC server
    log::info!("Starting RPC server for client {:?}!", mid);
    loop {
        let _handled = server
            .try_handle()
            .expect("Controller failed to handle RPC");
    }
}

pub(crate) fn poll_interface() {
    // Create RPC server connecting to DCM
    let transport = Box::try_new(
        TCPTransport::new(None, DCM_SERVER_PORT, Arc::clone(&ETHERNET_IFACE))
            .expect("Failed to create TCP transport"),
    )
    .expect("Out of memory during init");
    let mut server = Server::new(transport);
    server
        .register(DCMOps::NodeAssignment as RPCType, &NODE_ASSIGNMENT_HANDLER)
        .unwrap();
    let _ = server.add_client(&DCM_CLIENT_REGISTRAR).unwrap();
    log::info!("Added DCM server RPC client!");

    // Wait for all clients to initialize before signaling the all-clear
    while ClientReadyCount.load(Ordering::SeqCst) != (*crate::environment::NUM_MACHINES - 1) as u64
    {
    }
    ClientReadyCount.store(0, Ordering::SeqCst);

    // Don't modify this line without modifying testutils/rackscale_runner.rs
    log::warn!("CONTROLLER READY");

    // Now that server is ready, the clients may be accepted.
    DCMServerReady.store(true, Ordering::SeqCst);

    loop {
        match ETHERNET_IFACE.lock().poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }

        let _ = server.try_handle();
    }
}

fn register_rpcs(server: &mut Server) {
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
        .register(KernelRpc::ReleaseCore as RPCType, &REQUEST_CORE_HANDLER)
        .unwrap();
    server
        .register(
            KernelRpc::GetHardwareThreads as RPCType,
            &GET_HARDWARE_THREADS_HANDLER,
        )
        .unwrap();
    server
        .register(
            KernelRpc::GetShmemStructure as RPCType,
            &GET_SHMEM_STRUCTURE_HANDLER,
        )
        .unwrap();
    server
        .register(
            KernelRpc::GetShmemFrames as RPCType,
            &GET_SHMEM_FRAMES_HANDLER,
        )
        .unwrap();
}
