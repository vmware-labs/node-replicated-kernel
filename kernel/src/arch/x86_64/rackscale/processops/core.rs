// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use super::super::dcm::dcm_request::make_dcm_request;
use super::super::get_local_pid;
use super::super::kernelrpc::*;

#[derive(Debug)]
pub(crate) struct RequestCoreReq {
    pub core_id: u64,
    pub entry_point: u64,
}
unsafe_abomonate!(RequestCoreReq: core_id, entry_point);

pub(crate) fn rpc_request_core(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    core_id: u64,
    entry_point: u64,
) -> Result<(u64, u64), RPCError> {
    debug!("RequestCore({:?}, {:?})", core_id, entry_point);

    // Construct request data
    let req = RequestCoreReq {
        core_id,
        entry_point,
    };
    let mut req_data = [0u8; core::mem::size_of::<RequestCoreReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            pid,
            KernelRpc::RequestCore as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("RequestCore() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_request_core(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse request
    let core_req = match unsafe { decode::<RequestCoreReq>(payload) } {
        Some((req, _)) => req,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let node = make_dcm_request(local_pid, true);

    // Construct and return result
    let res = KernelRpcRes {
        ret: convert_return(Ok((node, 0))),
    };
    construct_ret(hdr, payload, res)
}
