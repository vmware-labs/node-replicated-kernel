// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rpc::rpc::RPCType;
use rpc::RPCClient;

use super::{DCMNodeId, DCMOps, DCM_INTERFACE};

#[derive(Debug, Default)]
#[repr(C)]
struct NodeRegistrationRequest {
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
    node_id: DCMNodeId,
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

pub(crate) fn dcm_register_node(cores: u64, memslices: u64) -> DCMNodeId {
    // Create request and space for response
    let req = NodeRegistrationRequest { cores, memslices };
    let mut res = NodeRegistrationResponse { node_id: 0 };

    // Send call, get allocation response in return
    {
        DCM_INTERFACE
            .lock()
            .client
            .call(
                DCMOps::RegisterNode as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
            .expect("Failed to send register node RPC to DCM");
    }

    log::debug!("Received node id in response: {:?}", res.node_id);
    return res.node_id;
}
