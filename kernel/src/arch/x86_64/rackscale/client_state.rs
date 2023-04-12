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
use spin::{Mutex, Once};
use static_assertions as sa;

use kpi::process::FrameId;
use rpc::client::Client;
use rpc::rpc::RPCError;

use crate::arch::kcb::try_per_core_mem;
use crate::arch::rackscale::dcm::DCMNodeId;
use crate::arch::rackscale::fileops::rw::{RW_SHMEM_BUF, RW_SHMEM_BUF_LEN};
use crate::cmdline::Transport;
use crate::error::{KError, KResult};
use crate::fs::NrLock;
use crate::memory::{mcache::MCache, LARGE_PAGE_SIZE, SHARED_AFFINITY};
use crate::process::MAX_PROCESSES;

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
        for _i in 0..MAX_PROCESSES {
            per_process_base_pages.push(FrameCacheBase::new(SHARED_AFFINITY));
        }

        log::warn!("Finished initializing client state");
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

    pub(crate) fn add_frame(&self, fid: FrameId, node_id: DCMNodeId) -> KResult<()> {
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
}

/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref CLIENT_STATE: ClientState = ClientState::new();
}

pub(crate) fn create_client_rpc_shmem_buffers() {
    RW_SHMEM_BUF.call_once(|| {
        // We want to allocate our temp buffer in shared memory
        let original_affinity = {
            let pcm = try_per_core_mem().expect("Failed to get pcm when creating rw shmem buffer");
            let affinity = pcm.physical_memory.borrow().affinity;
            pcm.set_mem_affinity(SHARED_AFFINITY)
                .expect("Can't change affinity");
            affinity
        };

        let mut shared_buf = Vec::try_with_capacity(RW_SHMEM_BUF_LEN)
            .expect("Failed to allocate read/write shmem buf");
        shared_buf.resize(RW_SHMEM_BUF_LEN, 0u8);
        let mut shared_buf = shared_buf.into_boxed_slice();

        // Reset mem allocator to use per core memory again
        {
            let pcm = try_per_core_mem().expect("Failed to get pcm when creating rw shmem buffer");
            pcm.set_mem_affinity(original_affinity)
                .expect("Can't change affinity");
        }
        RefCell::new(shared_buf)
    });
}
