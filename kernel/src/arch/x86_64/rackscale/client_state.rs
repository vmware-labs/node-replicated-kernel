// Copyright © 2023 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;

use arrayvec::ArrayVec;
use fallible_collections::FallibleVecGlobal;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::Mutex;

use rpc::client::Client;
use rpc::rpc::RPCError;

use crate::arch::kcb::try_per_core_mem;
use crate::arch::rackscale::controller::CONTROLLER_PORT_BASE;
use crate::arch::rackscale::FrameCacheBase;
use crate::arch::MAX_MACHINES;
use crate::cmdline::Transport;
use crate::error::{KError, KResult};
use crate::memory::backends::MemManager;
use crate::memory::shmem_affinity::{local_shmem_affinity, mid_to_shmem_affinity};
use crate::process::MAX_PROCESSES;

/// This is the state the client records about itself
pub(crate) struct ClientState {
    /// The RPC client used to communicate with the controller
    pub(crate) rpc_client: Client,

    /// Used to store shmem affinity base pages
    pub(crate) affinity_base_pages: Arc<ArrayVec<Mutex<Box<dyn MemManager + Send>>, MAX_MACHINES>>,

    /// Used to store base pages allocated to a process
    pub(crate) per_process_base_pages: Arc<ArrayVec<Mutex<FrameCacheBase>, MAX_PROCESSES>>,
}

impl ClientState {
    pub(crate) fn new() -> ClientState {
        // Create network stack and instantiate RPC Client
        let rpc_client = if crate::CMDLINE
            .get()
            .map_or(false, |c| c.transport == Transport::Ethernet)
        {
            crate::transport::ethernet::init_ethernet_rpc(
                Some((
                    smoltcp::wire::IpAddress::v4(172, 31, 0, 11),
                    CONTROLLER_PORT_BASE + (*crate::environment::MACHINE_ID as u16 - 1),
                )),
                CONTROLLER_PORT_BASE,
                atopology::MACHINE_TOPOLOGY.num_threads() as u8,
                true,
            )
            .expect("Failed to initialize ethernet RPC")
        } else {
            // Default is Shmem, even if transport unspecified
            crate::transport::shmem::init_shmem_rpc(true).expect("Failed to initialize shmem RPC")
        };

        let mut per_process_base_pages = ArrayVec::new();
        for _i in 0..MAX_PROCESSES {
            // TODO(rackscale): this is a bogus affinity because it should really be "ANY_SHMEM"
            per_process_base_pages.push(Mutex::new(FrameCacheBase::new(local_shmem_affinity())));
        }

        let mut affinity_base_pages = ArrayVec::new();
        for i in 0..MAX_MACHINES {
            affinity_base_pages.push(Mutex::new(Box::new(FrameCacheBase::new(
                mid_to_shmem_affinity(i),
            )) as Box<dyn MemManager + Send>));
        }

        log::debug!("Finished initializing client state");
        ClientState {
            rpc_client,
            affinity_base_pages: Arc::new(affinity_base_pages),
            per_process_base_pages: Arc::new(per_process_base_pages),
        }
    }
}

/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref CLIENT_STATE: ClientState = ClientState::new();
}
