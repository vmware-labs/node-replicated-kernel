// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::{Lazy, Mutex};

use rpc::api::{RPCClient, RPCHandler, RegistrationHandler};
use rpc::client::Client;
use rpc::rpc::{ClientId, RPCError, RPCHeader};

use crate::arch::rackscale::processops::request_core::request_core_work;
use crate::cmdline::Transport;
use crate::error::KError;
use crate::fs::NrLock;
use crate::transport::shmem::SHMEM_REGION;

/// A handle to an RPC client
///
/// This is used to send requests to a remote control-plane.
lazy_static! {
pub(crate) static ref RPC_CLIENT: Arc<Mutex<Box<Client>>> =
    // Create network stack and instantiate RPC Client
    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        // To support alloc_phys, client needs shared memory to be mapped
        lazy_static::initialize(&SHMEM_REGION);

        Arc::new(Mutex::new(
            crate::transport::ethernet::init_ethernet_rpc(
                smoltcp::wire::IpAddress::v4(172, 31, 0, 11),
                6970,
                true,
            )
            .expect("Failed to initialize ethernet RPC"),
        ))
    } else {
        // Default is Shmem, even if transport unspecified
        Arc::new(Mutex::new(
            crate::transport::shmem::init_shmem_rpc(true).expect("Failed to initialize shmem RPC"),
        ))
    };
}

// Mapping between local frame IDs and remote memory address space ID (node id, currently).
lazy_static! {
    pub(crate) static ref FRAME_MAP: NrLock<HashMap<u64, u64>> = NrLock::default();
}

// Lookup the address space corresponding to a local frame
pub(crate) fn get_frame_as(frame_id: u64) -> Result<u64, RPCError> {
    let frame_lookup = FRAME_MAP.read();
    let ret = frame_lookup.get(&frame_id);
    if let Some(addr_space) = ret {
        Ok(*addr_space)
    } else {
        Err(RPCError::InternalError)
    }
}

pub(crate) fn get_num_clients() -> ClientId {
    (crate::CMDLINE.get().map_or(2, |c| c.workers) - 1) as ClientId
}

pub(crate) fn get_local_client_id() -> ClientId {
    (crate::CMDLINE.get().map_or(1, |c| c.machine_id) - 1) as ClientId
}

pub(crate) fn client_get_work() -> () {
    let mut client = RPC_CLIENT.lock();
    request_core_work(&mut **client);
}
