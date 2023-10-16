// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use kpi::system::MachineId;
use rpc::rpc::RPCType;

use super::{DCMOps, DCM_CLIENT};

#[derive(Debug, Default)]
#[repr(C)]
struct ResourceReleaseRequest {
    mid: u64,
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

pub(crate) fn dcm_resource_release(mid: MachineId, pid: usize, is_core: bool) -> u64 {
    let req = ResourceReleaseRequest {
        mid: mid as u64,
        application: pid as u64,
        cores: if is_core { 1 } else { 0 },
        memslices: if is_core { 0 } else { 1 },
    };
    let mut res = ResourceReleaseResponse { is_success: 0 };
    log::debug!("Sending DCM a resource release request");

    // Send call, get allocation response in return
    {
        DCM_CLIENT
            .lock()
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
