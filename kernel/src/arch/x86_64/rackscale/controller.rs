// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
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

use kpi::system::CpuThread;
use rpc::api::RPCServer;
use rpc::rpc::{ClientId, RPCType};
use rpc::server::Server;

use crate::arch::debug::shutdown;
use crate::arch::rackscale::client::get_num_clients;
use crate::arch::rackscale::dcm::*;
use crate::arch::rackscale::processops::request_core::RequestCoreReq;
use crate::cmdline::Transport;
use crate::error::KError;
use crate::fs::{cnrfs, NrLock};
use crate::memory::backends::AllocatorStatistics;
use crate::memory::mcache::MCache;
use crate::memory::LARGE_PAGE_SIZE;
use crate::nr;
use crate::process::Pid;
use crate::transport::ethernet::ETHERNET_IFACE;
use crate::transport::shmem::create_shmem_manager;
use crate::ExitReason;

use super::*;

const PORT: u16 = 6970;

/// A cache of pages
/// TODO: think about how we should constrain this?
///
/// Used to allocate remote memory (in large chunks)
pub(crate) type FrameCacheMemslice = MCache<2048, 2048>;
sa::const_assert!(core::mem::size_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);

// Mapping between local PIDs and remote (client) PIDs.
// Using (ClientId, Pid) works as long as each ClientId has it's own
// unique Pid space.
lazy_static! {
    static ref PID_MAP: NrLock<HashMap<(ClientId, Pid), Pid>> = NrLock::default();
}

lazy_static! {
    pub(crate) static ref SHMEM_MANAGERS: Arc<Mutex<Vec<Option<Box<FrameCacheMemslice>>>>> = {
        let mut shmem_manager_vec = Vec::try_with_capacity(get_num_clients() as usize)
            .expect("Failed to create vector of shmem managers");
        for i in 0..get_num_clients() {
            shmem_manager_vec.push(None);
        }
        Arc::new(Mutex::new(shmem_manager_vec))
    };
}

// List of hwthreads of all the clients in the rack
lazy_static! {
    pub(crate) static ref HWTHREADS: Arc<Mutex<Vec<CpuThread>>> = {
        let mut hwthreads = Vec::try_with_capacity(get_num_clients() as usize)
            .expect("Failed to create vector for rack cpu threads");
        Arc::new(Mutex::new(hwthreads))
    };
}

// Keep track of which hwthreads have been allocated. Index corresponds to gtid of hwthread
lazy_static! {
    pub(crate) static ref HWTHREADS_BUSY: Arc<Mutex<Vec<Option<bool>>>> = {
        // Assume each client has about 8 cores, for now
        let mut hwthreads_busy = Vec::try_with_capacity(get_num_clients() as usize * 8)
            .expect("Failed to create vector for rack cpu threads");
        for i in 0..(get_num_clients() as usize * 30) {
            hwthreads_busy.push(None);
        }
        Arc::new(Mutex::new(hwthreads_busy))
    };
}

// Keep track of unfulfilled core assignments
lazy_static! {
    pub(crate) static ref UNFULFILLED_CORE_ASSIGNMENTS: Arc<Mutex<Vec<Box<VecDeque<RequestCoreReq>>>>> = {
        let mut core_assignments = Vec::try_with_capacity(get_num_clients() as usize)
            .expect("Failed to create vector for core requests");
        for i in 0..get_num_clients() {
            // TODO: how to size vector appropriately? No try method for VecDeque
            let mut client_core_assignments = VecDeque::with_capacity(3 as usize);
            core_assignments.push(Box::new(client_core_assignments))
        }
        Arc::new(Mutex::new(core_assignments))
    };
}

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
    let num_clients = get_num_clients();
    let mut servers: Vec<Box<dyn RPCServer>> = Vec::try_with_capacity(num_clients as usize)
        .expect("Failed to allocate vector for RPC server");
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
        for client_id in 0..=(num_clients - 1) {
            let transport = Box::try_new(
                create_shmem_transport(client_id).expect("Failed to create shmem transport"),
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
            KernelRpc::RequestWork as RPCType,
            &REQUEST_CORE_WORK_HANDLER,
        )
        .unwrap();

    server
        .register(
            KernelRpc::GetHardwareThreads as RPCType,
            &GET_HARDWARE_THREADS_HANDLER,
        )
        .unwrap();
}

// Lookup the local pid corresponding to a remote pid
pub(crate) fn get_local_pid(client_id: ClientId, remote_pid: usize) -> Result<usize, KError> {
    {
        let process_lookup = PID_MAP.read();
        let local_pid = process_lookup.get(&(client_id, remote_pid));
        if let Some(pid) = local_pid {
            return Ok(*(local_pid.unwrap()));
        }
    }

    // TODO: will eventually want to delete this logic, as we should create
    // mapping on process creation.
    warn!(
        "Failed to lookup remote pid {}:{}, will register locally instead",
        client_id, remote_pid
    );
    register_pid(client_id, remote_pid)
}

// Register a remote pid by creating a local pid and creating a remote-local PID mapping
pub(crate) fn register_pid(client_id: ClientId, remote_pid: usize) -> Result<usize, KError> {
    crate::nr::NR_REPLICA
        .get()
        .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
            let response = replica.execute_mut(nr::Op::AllocatePid, *token)?;
            if let nr::NodeResult::PidAllocated(local_pid) = response {
                // TODO: some way to unwind if fails??
                match cnrfs::MlnrKernelNode::add_process(local_pid) {
                    Ok(_) => {
                        // TODO: register pid
                        debug!("register_pid about to get PID_MAP");
                        let mut pmap = PID_MAP.write();
                        pmap.try_reserve(1)?;
                        debug!(
                            "Mapped remote pid {} to local pid {}",
                            remote_pid, local_pid
                        );
                        pmap.try_insert((client_id, remote_pid), local_pid)
                            .map_err(|_e| KError::FileDescForPidAlreadyAdded)?;
                        Ok(local_pid)
                    }
                    Err(err) => {
                        error!("Unable to register pid {:?} {:?}", remote_pid, err);
                        Err(KError::NoProcessFoundForPid)
                    }
                }
            } else {
                Err(KError::NoProcessFoundForPid)
            }
        })
}
