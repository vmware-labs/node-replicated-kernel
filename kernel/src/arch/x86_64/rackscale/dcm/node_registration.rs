// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
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
pub struct NodeRegistrationRequest {
    pub cores: u64,
    pub memslices: u64,
}
pub const REQ_SIZE: usize = core::mem::size_of::<NodeRegistrationRequest>();

impl NodeRegistrationRequest {
    /// # Safety
    /// - `self` must be valid NodeRegistrationRequest
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const NodeRegistrationRequest) as *mut u8,
            REQ_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid NodeRegistrationRequest
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
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
pub struct NodeRegistrationResponse {
    pub node_id: u64,
}
pub const RES_SIZE: usize = core::mem::size_of::<NodeRegistrationResponse>();

impl NodeRegistrationResponse {
    /// # Safety
    /// - `self` must be valid NodeRegistrationResponse
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const NodeRegistrationResponse) as *mut u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid NodeRegistrationResponse
    pub unsafe fn as_bytes(&self) -> &[u8; RES_SIZE] {
        ::core::slice::from_raw_parts(
            (self as *const NodeRegistrationResponse) as *const u8,
            RES_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

pub(crate) fn dcm_register_node(local_pid: usize, cores: u64, memslices: u64) -> u64 {
    // Create request and space for response
    let req = NodeRegistrationRequest { cores, memslices };
    let mut res = NodeRegistrationResponse { node_id: 0 };

    // Send call, get allocation response in return
    {
        DCM_INTERFACE
            .lock()
            .client
            .call(
                local_pid,
                DCMOps::RegisterNode as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
            .unwrap();
        debug!("Received node id in response: {:?}", res.node_id);
    }
    return res.node_id;
}
