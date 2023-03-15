// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, warn};
use rpc::rpc::RPCType;
use rpc::RPCClient;
use smoltcp::socket::UdpSocket;
use smoltcp::time::Instant;

use crate::transport::ethernet::ETHERNET_IFACE;

use super::super::kernelrpc::*;
use super::{DCMNodeId, DCMOps, DCM_INTERFACE};

#[derive(Debug, Default)]
#[repr(C)]
pub struct AffinityAllocReq {
    pub node_id: DCMNodeId,
    pub num_cores: u64,
    pub num_memslices: u64,
}
pub const REQ_SIZE: usize = core::mem::size_of::<AffinityAllocReq>();

impl AffinityAllocReq {
    /// # Safety
    /// - `self` must be valid AffinityAllocReq
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AffinityAllocReq) as *mut u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AffinityAllocReq
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts((self as *const AffinityAllocReq) as *const u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AffinityAllocRes {
    pub can_satisfy: bool,
}
pub const RES_SIZE: usize = core::mem::size_of::<AffinityAllocRes>();

impl AffinityAllocRes {
    /// # Safety
    /// - `self` must be valid AffinityAllocRes
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AffinityAllocRes) as *mut u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AffinityAllocRes
    pub unsafe fn as_bytes(&self) -> &[u8; RES_SIZE] {
        ::core::slice::from_raw_parts((self as *const AffinityAllocRes) as *const u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_affinity_alloc(node_id: DCMNodeId, num_memslices: usize) -> bool {
    let req = AffinityAllocReq {
        node_id,
        num_cores: 0,
        num_memslices: num_memslices as u64,
    };
    log::debug!(
        "dcm_affinity_alloc({:?}, {:?}, {:?})",
        node_id,
        0,
        num_memslices
    );
    let mut res = AffinityAllocRes { can_satisfy: false };

    DCM_INTERFACE
        .lock()
        .client
        .call(
            DCMOps::AffinityAlloc as RPCType,
            unsafe { &[req.as_bytes()] },
            unsafe { &mut [res.as_mut_bytes()] },
        )
        .expect("Failed to send resource alloc RPC to DCM");
    debug!("Can the allocation be satisfied? {:?}", res.can_satisfy);
    return res.can_satisfy;
}
