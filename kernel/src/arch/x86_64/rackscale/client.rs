// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use spin::{Lazy, Mutex};

use rpc::api::{RPCClient, RPCHandler, RegistrationHandler};
use rpc::rpc::{ClientId, RPCError, RPCHeader};

use crate::cmdline::Transport;
use crate::transport::shmem::SHMEM_REGION;

/// A handle to an RPC client
///
/// This is used to send requests to a remote control-plane.
#[thread_local]
pub(crate) static RPC_CLIENT: Lazy<Mutex<Box<dyn RPCClient>>> = Lazy::new(|| {
    // Create network stack and instantiate RPC Client
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
                true,
            )
            .expect("Failed to initialize ethernet RPC"),
        )
    } else {
        // Default is Shmem, even if transport unspecified
        Mutex::new(
            crate::transport::shmem::init_shmem_rpc(true).expect("Failed to initialize shmem RPC"),
        )
    };
});

pub(crate) fn get_num_clients() -> u64 {
    (crate::CMDLINE.get().map_or(2, |c| c.workers) - 1) as u64
}

pub(crate) fn get_local_client_id() -> u64 {
    (crate::CMDLINE.get().map_or(1, |c| c.machine_id) - 1) as u64
}
