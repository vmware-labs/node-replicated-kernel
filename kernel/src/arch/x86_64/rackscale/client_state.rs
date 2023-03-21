// Copyright © 2023 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use arrayvec::ArrayVec;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::{Lazy, Mutex};
use static_assertions as sa;

use kpi::process::FrameId;
use rpc::api::{RPCClient, RPCHandler, RegistrationHandler};
use rpc::client::Client;
use rpc::rpc::{RPCError, RPCHeader};

use crate::arch::rackscale::dcm::DCMNodeId;
use crate::arch::rackscale::processops::core_work::rpc_core_work;
use crate::cmdline::Transport;
use crate::error::KError;
use crate::fs::NrLock;
use crate::memory::{mcache::MCache, LARGE_PAGE_SIZE, SHARED_AFFINITY};
use crate::process::MAX_PROCESSES;
use crate::transport::shmem::SHMEM_DEVICE;

/// A cache of base pages
/// TODO(rackscale): think about how we should constrain this?
///
/// Used locally on the client, since only large pages are allocated by the controller.
pub(crate) type FrameCacheBase = MCache<2048, 0>;
sa::const_assert!(core::mem::size_of::<FrameCacheBase>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheBase>() <= LARGE_PAGE_SIZE);

/// This is the state the client records about itself
pub(crate) struct ClientState {
    /// The RPC client used to communicate with the controller
    pub(crate) rpc_client: Arc<Mutex<Box<Client>>>,

    /// Mapping between local frame IDs and remote memory address space ID.
    frame_map: NrLock<HashMap<FrameId, DCMNodeId>>,

    /// Used to store affinity base pages
    pub(crate) base_pages: Arc<Mutex<FrameCacheBase>>,

    /// Used to store base pages allocated to a process
    pub(crate) per_process_base_pages: Arc<Mutex<ArrayVec<FrameCacheBase, MAX_PROCESSES>>>,
}

impl ClientState {
    pub(crate) fn new() -> ClientState {
        // Create network stack and instantiate RPC Client
        let rpc_client = if crate::CMDLINE
            .get()
            .map_or(false, |c| c.transport == Transport::Ethernet)
        {
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
                crate::transport::shmem::init_shmem_rpc(true)
                    .expect("Failed to initialize shmem RPC"),
            ))
        };

        let mut per_process_base_pages = ArrayVec::new();
        for i in 0..MAX_PROCESSES {
            per_process_base_pages.push(FrameCacheBase::new(SHARED_AFFINITY));
        }

        ClientState {
            rpc_client,
            frame_map: NrLock::default(),
            base_pages: Arc::new(Mutex::new(FrameCacheBase::new(SHARED_AFFINITY))),
            per_process_base_pages: Arc::new(Mutex::new(per_process_base_pages)),
        }
    }

    // Lookup the address space identifier (currently, the DCMNodeId) corresponding to a local frame
    pub(crate) fn get_frame_as(&self, frame_id: FrameId) -> Result<DCMNodeId, RPCError> {
        let frame_lookup = self.frame_map.read();
        let ret = frame_lookup.get(&frame_id);
        if let Some(addr_space) = ret {
            Ok(*addr_space)
        } else {
            Err(RPCError::InternalError)
        }
    }

    pub(crate) fn add_frame(&self, fid: FrameId, node_id: DCMNodeId) -> Result<(), KError> {
        let mut frame_map = self.frame_map.write();
        frame_map
            .try_reserve(1)
            .map_err(|_e| KError::NotEnoughMemory)?;
        frame_map
            .try_insert(fid, node_id)
            .map_err(|_e| KError::InvalidFrame)?;
        log::info!(
            "Inserted local frame {} to address space (node) {}",
            fid,
            node_id
        );
        Ok(())
    }

    pub(crate) fn remove_frame(&self, fid: FrameId) -> Result<(), RPCError> {
        let mut frame_map = self.frame_map.write();
        frame_map.remove(&fid).expect("Didn't find a frame for fid");
        Ok(())
    }

    // TODO(hunhoffe): get rid of this.
    pub(crate) fn client_get_work(&self) -> () {
        let mut client = self.rpc_client.lock();
        rpc_core_work(&mut **client);
    }
}

/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref CLIENT_STATE: ClientState = ClientState::new();
}
