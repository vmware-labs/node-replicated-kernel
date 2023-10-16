// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use fallible_collections::FallibleVecGlobal;

use kpi::system::MachineId;
use rpc::rpc::RPCType;

use super::super::kernelrpc::*;
use super::{DCMOps, DCM_CLIENT, IN_FLIGHT_DCM_ASSIGNMENTS};

#[derive(Debug, Default)]
#[repr(C)]
struct ResourceAllocRequest {
    application: u64,
    cores: u64,
    memslices: u64,
}
const REQ_SIZE: usize = core::mem::size_of::<ResourceAllocRequest>();

impl ResourceAllocRequest {
    /// # Safety
    /// - `self` must be valid ResourceAllocRequest
    unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts((self as *const ResourceAllocRequest) as *const u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
struct ResourceAllocResponse {
    alloc_id: u64,
}
const RES_SIZE: usize = core::mem::size_of::<ResourceAllocResponse>();

impl ResourceAllocResponse {
    /// # Safety
    /// - `self` must be valid ResourceAllocResponse
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const ResourceAllocResponse) as *mut u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_resource_alloc(
    pid: usize,
    cores: u64,
    memslices: u64,
) -> (Vec<MachineId>, Vec<MachineId>) {
    // TODO(rackscale): make debug assert
    assert!(cores > 0 || memslices > 0);
    log::debug!(
        "Asking DCM for {:?} cores and {:?} memslices for pid {:?}",
        cores,
        memslices,
        pid
    );

    let req = ResourceAllocRequest {
        application: pid as u64,
        cores,
        memslices,
    };

    let mut res = ResourceAllocResponse { alloc_id: 0 };

    // Send call, get allocation response in return
    {
        DCM_CLIENT
            .lock()
            .call(
                DCMOps::ResourceAlloc as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
            .expect("Failed to send resource alloc RPC to DCM");
    }
    log::debug!("Received allocation id in response: {:?}", res.alloc_id);

    // Insert allocation IDs to be processed.
    let mut assignments = Vec::try_with_capacity((cores + memslices) as usize)
        .expect("Failed to get memory to assignment array");
    for i in 0..(cores + memslices) {
        let assignment_id = Arc::new(AtomicU64::new(0));
        assignments.push(assignment_id);
    }

    let mut received_allocations = 0;
    let mut dcm_node_for_cores =
        Vec::try_with_capacity(cores as usize).expect("Failed to allocate memory");
    let mut dcm_node_for_memslices =
        Vec::try_with_capacity(memslices as usize).expect("Failed to allocate memory");

    {
        let mut assignment_table = IN_FLIGHT_DCM_ASSIGNMENTS.lock();
        for i in 0..(cores + memslices) {
            // If it's already been added to the table, record the allocation
            if let Some(node_assignment) =
                assignment_table.insert(res.alloc_id + i, assignments[i as usize].clone())
            {
                let assigned_node = node_assignment.load(Ordering::SeqCst);
                if i < cores {
                    dcm_node_for_cores.push(assigned_node as MachineId);
                } else {
                    dcm_node_for_memslices.push(assigned_node as MachineId);
                }
                received_allocations += 1;
                assignment_table.remove(&(res.alloc_id + 1));
            }
        }
    }

    // Wait for assignments by checking hash map
    while received_allocations < cores + memslices {
        let assigned_node = assignments[received_allocations as usize].load(Ordering::SeqCst);

        // Assignment is fulfilled!
        if assigned_node != 0 {
            // Remove from hash map
            {
                let mut assignment_table = IN_FLIGHT_DCM_ASSIGNMENTS.lock();
                assignment_table.remove(&(received_allocations + res.alloc_id));
            }

            // Record the assignment
            log::debug!(
                "Received assignment: {:?} to node {:?}",
                received_allocations + res.alloc_id,
                assigned_node
            );
            if received_allocations < cores {
                dcm_node_for_cores.push(assigned_node as MachineId);
            } else {
                dcm_node_for_memslices.push(assigned_node as MachineId);
            }
            received_allocations += 1;
        }
    }
    log::debug!(
        "Received resources from DCM for {:?} cores and {:?} memslices for pid {:?}, assignments: {:?}",
        cores,
        memslices,
        pid,
        assignments
    );
    (dcm_node_for_cores, dcm_node_for_memslices)
}
