// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::kernelrpc::*;
use super::FileIO;
use crate::arch::rackscale::controller::get_local_pid;

pub(crate) fn rpc_delete(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    pathname: String,
) -> Result<(u64, u64), RPCError> {
    debug!("Delete({:?})", pathname);

    // Create buffer for result
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call RPC
    rpc_client
        .call(
            pid,
            KernelRpc::Delete as RPCType,
            &[&pathname.as_bytes()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode result - return result if decoding successful
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Delete() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_delete(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();
    let path = core::str::from_utf8(&payload[..hdr.msg_len as usize])?;

    // Construct and return result
    let res = KernelRpcRes {
        ret: convert_return(cnrfs::MlnrKernelNode::file_delete(
            local_pid,
            TryString::try_from(path)?.into(), // TODO(fixme): unnecessary allocation
        )),
    };
    construct_ret(hdr, payload, res)
}
