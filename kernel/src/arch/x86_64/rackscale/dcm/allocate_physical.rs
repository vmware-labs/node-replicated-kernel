// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::super::syscall_res::*;
use super::get_local_pid;
use super::ResourceRequest;
use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

#[derive(Debug)]
pub(crate) struct AllocatePhysicalRequest {
    pub page_size: u64,
    pub affinity: u64,
}
unsafe_abomonate!(AllocatePhysicalRequest: page_size, affinity);

pub(crate) fn rpc_allocate_phsyical(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    page_size: u64,
    affinity: u64,
) -> Result<(u64, u64), RPCError> {
    debug!("AllocatePhysical({:?}, {:?})", page_size, affinity);

    // Construct request data
    let req = AllocatePhysicalRequest {
        page_size,
        affinity,
    };
    let mut req_data = [0u8; core::mem::size_of::<AllocatePhysicalRequest>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<SyscallRes>()];
    rpc_client
        .call(
            pid,
            ResourceRequest::Memory as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<SyscallRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("AllocatePhysical() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_allocate_physical(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse request
    let core_req = match unsafe { decode::<AllocatePhysicalRequest>(payload) } {
        Some((req, _)) => req,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    // Construct and return result
    let res = SyscallRes {
        ret: convert_return(Ok((0, 0))),
    };
    construct_ret(hdr, payload, res)
}
