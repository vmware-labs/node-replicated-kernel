// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, warn};
use rpc::rpc::RPCType;
use rpc::RPCClient;
use smoltcp::socket::UdpSocket;
use smoltcp::time::Instant;

use crate::transport::ethernet::ETHERNET_IFACE;

use super::super::kernelrpc::*;
use super::{DCMOps, DCM_INTERFACE};

#[derive(Debug, Default)]
#[repr(C)]
pub struct ResourceReleaseRequest {
    pub node_id: u64,
    pub application: u64,
    pub cores: u64,
    pub memslices: u64,
}
pub const REQ_SIZE: usize = core::mem::size_of::<ResourceReleaseRequest>();

impl ResourceReleaseRequest {
    /// # Safety
    /// - `self` must be valid ResourceReleaseRequest
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const ResourceReleaseRequest) as *mut u8,
            REQ_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid ResourceReleaseRequest
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
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
pub struct ResourceReleaseResponse {
    pub is_success: u64,
}
pub const RES_SIZE: usize = core::mem::size_of::<ResourceReleaseResponse>();

impl ResourceReleaseResponse {
    /// # Safety
    /// - `self` must be valid ResourceReleaseResponse
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const ResourceReleaseResponse) as *mut u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid ResourceReleaseResponse
    pub unsafe fn as_bytes(&self) -> &[u8; RES_SIZE] {
        ::core::slice::from_raw_parts(
            (self as *const ResourceReleaseResponse) as *const u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_resource_release(node_id: u64, local_pid: usize, is_core: bool) -> u64 {
    let req = ResourceReleaseRequest {
        node_id,
        application: 1, // TODO: filler for application for now
        cores: if is_core { 1 } else { 0 },
        memslices: if is_core { 0 } else { 1 },
    };
    let mut res = ResourceReleaseResponse { is_success: 0 };

    // Send call, get allocation response in return
    DCM_INTERFACE
        .lock()
        .client
        .call(
            local_pid,
            DCMOps::ResourceRelease as RPCType,
            unsafe { &[req.as_bytes()] },
            unsafe { &mut [res.as_mut_bytes()] },
        )
        .unwrap();
    debug!(
        "Received is_success for DCM resource release: {:?}",
        res.is_success
    );
    return res.is_success;
}
