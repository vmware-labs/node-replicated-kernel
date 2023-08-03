// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use kpi::system::MachineId;
use rpc::rpc::RPCType;

use super::{DCMOps, DCM_CLIENT};

#[derive(Debug, Default)]
#[repr(C)]
struct NodeRegistrationRequest {
    mid: u64,
    cores: u64,
    memslices: u64,
}
const REQ_SIZE: usize = core::mem::size_of::<NodeRegistrationRequest>();

impl NodeRegistrationRequest {
    /// # Safety
    /// - `self` must be valid NodeRegistrationRequest
    unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts(
            (self as *const NodeRegistrationRequest) as *const u8,
            REQ_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
struct NodeRegistrationResponse {
    is_success: bool,
}
const RES_SIZE: usize = core::mem::size_of::<NodeRegistrationResponse>();

impl NodeRegistrationResponse {
    /// # Safety
    /// - `self` must be valid NodeRegistrationResponse
    unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const NodeRegistrationResponse) as *mut u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_register_node(mid: MachineId, cores: u64, memslices: u64) -> bool {
    // Create request and space for response
    let req = NodeRegistrationRequest {
        mid: mid as u64,
        cores,
        memslices,
    };
    let mut res = NodeRegistrationResponse { is_success: false };

    // Send call, get allocation response in return
    {
        DCM_CLIENT
            .lock()
            .call(
                DCMOps::RegisterNode as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
            .expect("Failed to send register node RPC to DCM");
    }

    log::debug!("Registered node is successful? {:?}", res.is_success);
    return res.is_success;
}
