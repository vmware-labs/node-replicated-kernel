// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use fallible_collections::FallibleVecGlobal;
use smoltcp::socket::UdpSocket;
use smoltcp::time::Instant;

use rpc::rpc::RPCType;
use rpc::RPCClient;

use crate::transport::ethernet::ETHERNET_IFACE;

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

#[derive(Debug, Default)]
#[repr(C)]
struct ResourceAllocAssignment {
    alloc_id: u64,
    node: DCMNodeId,
}
pub(crate) const ALLOC_LEN: usize = core::mem::size_of::<ResourceAllocAssignment>();

impl ResourceAllocAssignment {
    /// # Safety
    /// - `self` must be valid ResourceAllocAssignment
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts_mut(
            (self as *const ResourceAllocAssignment) as *mut u8,
            ALLOC_LEN,
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
    let mut assignment = ResourceAllocAssignment {
        alloc_id: 0,
        node: 0,
    };

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
        {
            let mut my_iface = ETHERNET_IFACE.lock();
            let socket = my_iface.get_socket::<UdpSocket>(DCM_INTERFACE.lock().udp_handle);
            if socket.can_recv() {
                match socket.recv_slice(unsafe { assignment.as_mut_bytes() }) {
                    Ok((_, endpoint)) => {
                        log::debug!(
                            "Received assignment: {:?} to node {:?}",
                            assignment.alloc_id,
                            assignment.node
                        );
                        if assignment.alloc_id > res.alloc_id + cores + memslices
                            || assignment.alloc_id < res.alloc_id
                        {
                            panic!("AllocIds do not match!");
                        }
                        socket
                            .send_slice(&[1u8], endpoint)
                            .expect("Failed to send UDP message to DCM");
                        if assignment.alloc_id - res.alloc_id < cores {
                            dcm_node_for_cores.push(assignment.node);
                        } else {
                            dcm_node_for_memslices.push(assignment.node);
                        }
                        received_allocations += 1;
                    }
                    Err(e) => {
                        log::debug!("Received nothing? {:?}", e);
                    }
                }
            }
        }

        match ETHERNET_IFACE.lock().poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("poll error: {}", e);
            }
        }
    }
    (dcm_node_for_cores, dcm_node_for_memslices)
}
