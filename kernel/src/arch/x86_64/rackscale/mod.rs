// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(warnings)]

use alloc::boxed::Box;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error, warn};
use rpc::api::{RPCClient, RPCHandler, RegistrationHandler};
use rpc::rpc::{ClientId, RPCError, RPCHeader};
use spin::{Lazy, Mutex};
use static_assertions as sa;

pub(crate) mod controller;
pub(crate) mod dcm;
pub(crate) mod error;
pub(crate) mod fileops;
pub(crate) mod kernelrpc;
pub(crate) mod processops;
pub(crate) mod syscalls;

use crate::cmdline::Transport;
use crate::error::KError;
use crate::fs::{cnrfs, NrLock};
use crate::memory::mcache::MCache;
use crate::memory::LARGE_PAGE_SIZE;
use crate::nr;
use crate::process::Pid;
use crate::transport::shmem::SHMEM_REGION;

use dcm::node_registration::dcm_register_node;

/// A cache of pages
/// TODO: think about how we should constrain this?
///
/// Used to allocate remote memory (in large chunks)
pub(crate) type FrameCacheMemslice = MCache<2048, 2048>;
sa::const_assert!(core::mem::size_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);

/// A handle to an RPC client
///
/// This is used to send requests to a remote control-plane.
#[thread_local]
pub(crate) static RPC_CLIENT: Lazy<Mutex<Box<dyn RPCClient>>> = Lazy::new(|| {
    // Create network stack and instantiate RPC Client
    let machine_id = crate::CMDLINE.get().map_or(0, |c| c.machine_id);
    return if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        // To support alloc_phys, client needs shared memory to be mapped
        lazy_static::initialize(&SHMEM_REGION);

        Mutex::new(
            crate::transport::ethernet::init_ethernet_rpc(
                smoltcp::wire::IpAddress::v4(172, 31, 0, 11),
                6970,
            )
            .expect("Failed to initialize ethernet RPC"),
        )
    } else {
        // Default is Shmem, even if transport unspecified
        Mutex::new(
            crate::transport::shmem::init_shmem_rpc(machine_id)
                .expect("Failed to initialize shmem RPC"),
        )
    };
});

// Mapping between local PIDs and remote (client) PIDs.
// Using (ClientId, Pid) works as long as each ClientId has it's own
// unique Pid space.
lazy_static! {
    static ref PID_MAP: NrLock<HashMap<(ClientId, Pid), Pid>> = NrLock::default();
}

// RPC Handler for client registration
pub(crate) fn register_client(hdr: &mut RPCHeader, _payload: &[u8]) -> Result<ClientId, RPCError> {
    // TODO: calculate cores and memslices more correctly
    let cores = 64;
    let memslices = SHMEM_REGION.size / LARGE_PAGE_SIZE as u64;

    // Register client resources with DCM, DCM doesn't care about pids, so
    // send w/ dummy pid
    let node_id = dcm_register_node(0, cores, memslices);
    log::info!(
        "Registered client {:?} with {:?} cores and {:?} memslices",
        node_id,
        cores,
        memslices
    );
    hdr.client_id = node_id;
    Ok(node_id)
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

pub(crate) use self::kernelrpc::KernelRpc;

// Re-export client registration
pub(crate) const CLIENT_REGISTRAR: RegistrationHandler = register_client;

// Re-export handlers: file operations
pub(crate) const CLOSE_HANDLER: RPCHandler = fileops::close::handle_close;
pub(crate) const DELETE_HANDLER: RPCHandler = fileops::delete::handle_delete;
pub(crate) const GETINFO_HANDLER: RPCHandler = fileops::getinfo::handle_getinfo;
pub(crate) const MKDIR_HANDLER: RPCHandler = fileops::mkdir::handle_mkdir;
pub(crate) const OPEN_HANDLER: RPCHandler = fileops::open::handle_open;
pub(crate) const RENAME_HANDLER: RPCHandler = fileops::rename::handle_rename;
pub(crate) const READ_HANDLER: RPCHandler = fileops::rw::handle_read;
pub(crate) const WRITE_HANDLER: RPCHandler = fileops::rw::handle_write;

// Re-export handdlers: process operations
pub(crate) const CORE_HANDLER: RPCHandler = processops::core::handle_request_core;
pub(crate) const ALLOC_HANDLER: RPCHandler = processops::mem::handle_phys_alloc;
pub(crate) const LOG_HANDLER: RPCHandler = processops::print::handle_log;
