// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use fallible_collections::FallibleVecGlobal;

use rpc::rpc::RPCType;
use rpc::RPCClient;
use rpc::RPCServer;

use super::super::kernelrpc::*;
use super::{DCMNodeId, DCMOps, DCM_INTERFACE};

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
) -> (Vec<DCMNodeId>, Vec<DCMNodeId>) {
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
        DCM_INTERFACE
            .lock()
            .client
            .call(
                DCMOps::ResourceAlloc as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
            .expect("Failed to send resource alloc RPC to DCM");
    }
    log::debug!("Received allocation id in response: {:?}", res.alloc_id);

    let mut received_allocations = 0;
    let mut dcm_node_for_cores =
        Vec::try_with_capacity(cores as usize).expect("Failed to allocate memory");
    let mut dcm_node_for_memslices =
        Vec::try_with_capacity(memslices as usize).expect("Failed to allocate memory");

    while received_allocations < cores + memslices {
        let dcm_interface = DCM_INTERFACE.lock();
        match dcm_interface.server.handle(None) {
            Ok(Some((alloc_id, node))) => {
                log::warn!("Received assignment: {:?} to node {:?}", alloc_id, node);
                if alloc_id > res.alloc_id + cores + memslices || alloc_id < res.alloc_id {
                    panic!("AllocIds do not match!");
                }
                if alloc_id - res.alloc_id < cores {
                    dcm_node_for_cores.push(node);
                } else {
                    dcm_node_for_memslices.push(node);
                }
                received_allocations += 1;
            }
            Err(err) => {
                log::error!("Failed to get assignment from DCM: {:?}", err);
                panic!("Failed to get assignment from DCM");
            }
            _ => unreachable!("Should not reach here"),
        }
    }
    (dcm_node_for_cores, dcm_node_for_memslices)
}
