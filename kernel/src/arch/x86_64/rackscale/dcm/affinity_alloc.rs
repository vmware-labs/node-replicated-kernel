// Copyright © 2023 University of Colorado Boulder and VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use kpi::system::MachineId;
use rpc::rpc::RPCType;

use super::super::controller_state::SHMEM_MEMSLICE_ALLOCATORS;
use super::super::get_shmem_frames::ShmemRegion;
use super::super::kernelrpc::*;
use super::{DCMOps, DCM_CLIENT};
use crate::error::{KError, KResult};
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::shmem_affinity::mid_to_shmem_affinity;

#[derive(Debug, Default)]
#[repr(C)]
struct AffinityAllocReq {
    mid: u64,
    num_cores: u64,
    num_memslices: u64,
}
const REQ_SIZE: usize = core::mem::size_of::<AffinityAllocReq>();

impl AffinityAllocReq {
    /// # Safety
    /// - `self` must be valid AffinityAllocReq
    pub(crate) unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts((self as *const AffinityAllocReq) as *const u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
struct AffinityAllocRes {
    pub(crate) can_satisfy: bool,
}
const RES_SIZE: usize = core::mem::size_of::<AffinityAllocRes>();

impl AffinityAllocRes {
    /// # Safety
    /// - `self` must be valid AffinityAllocRes
    pub(crate) unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AffinityAllocRes) as *mut u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_affinity_alloc(
    mid: MachineId,
    num_memslices: usize,
) -> KResult<Vec<ShmemRegion>> {
    // controller (mid == 0) shmem is not managed by DCM
    assert!(mid != 0);
    debug_assert!(num_memslices > 0);
    log::debug!(
        "dcm_affinity_alloc(mid={:?}, cores={:?}, memslices={:?})",
        mid,
        0,
        num_memslices
    );

    // Prepare RPC request and return
    let req = AffinityAllocReq {
        mid: mid as u64,
        num_cores: 0,
        num_memslices: num_memslices as u64,
    };
    let mut res = AffinityAllocRes { can_satisfy: false };

    // Ask DCM to make sure we can safely take from the shmem allocators
    log::debug!("Calling DCM for affinity alloc request");
    DCM_CLIENT.lock().call(
        DCMOps::AffinityAlloc as RPCType,
        unsafe { &[req.as_bytes()] },
        unsafe { &mut [res.as_mut_bytes()] },
    )?;
    log::debug!("Finished calling DCM for affinity alloc request");

    // TODO(rackscales): if it fails, ask for memory from somewhere else??
    // Maybe implement this with a boolean "force" mode?
    if !res.can_satisfy {
        log::error!("dcm_affinity_alloc failed due to lack of memory");
        return Err(KError::DCMNotEnoughMemory);
    }

    // Take the frames from the shmem allocator belonging to the requested mid
    let mut regions = Vec::<ShmemRegion>::new();
    {
        let mut manager = &mut SHMEM_MEMSLICE_ALLOCATORS[mid - 1].lock();
        for _i in 0..num_memslices {
            let frame = manager
                .allocate_large_page()
                .expect("DCM OK'd allocation, this should succeed");
            assert!(frame.affinity == mid_to_shmem_affinity(mid));
            regions.push(ShmemRegion {
                base: frame.base.as_u64(),
                affinity: frame.affinity,
            });
        }
    }
    return Ok(regions);
}
