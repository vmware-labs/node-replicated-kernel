// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rpc::rpc::RPCType;
use rpc::RPCClient;
use smoltcp::socket::UdpSocket;
use smoltcp::time::Instant;

use super::super::kernelrpc::*;
use super::{DCMNodeId, DCMOps, DCM_INTERFACE};
use crate::transport::ethernet::ETHERNET_IFACE;

#[derive(Debug, Default)]
#[repr(C)]
struct ResourceReleaseRequest {
    node_id: DCMNodeId,
    application: u64,
    cores: u64,
    memslices: u64,
}
const REQ_SIZE: usize = core::mem::size_of::<ResourceReleaseRequest>();

impl ResourceReleaseRequest {
    /// # Safety
    /// - `self` must be valid ResourceReleaseRequest
    unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts(
            (self as *const ResourceReleaseRequest) as *const u8,
            REQ_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
struct ResourceReleaseResponse {
    is_success: u64,
}
const RES_SIZE: usize = core::mem::size_of::<ResourceReleaseResponse>();

impl ResourceReleaseResponse {
    /// # Safety
    /// - `self` must be valid ResourceReleaseResponse
    unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const ResourceReleaseResponse) as *mut u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_resource_release(node_id: DCMNodeId, pid: usize, is_core: bool) -> u64 {
    let req = ResourceReleaseRequest {
        node_id: node_id,
        application: pid as u64,
        cores: if is_core { 1 } else { 0 },
        memslices: if is_core { 0 } else { 1 },
    };
    let mut res = ResourceReleaseResponse { is_success: 0 };

    // Send call, get allocation response in return
    {
        DCM_INTERFACE
            .lock()
            .client
            .call(
                DCMOps::ResourceRelease as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
            .expect("Failed to send resource release RPC to DCM");
    }
    log::debug!(
        "Received is_success for DCM resource release: {:?}",
        res.is_success
    );
    return res.is_success;
}
