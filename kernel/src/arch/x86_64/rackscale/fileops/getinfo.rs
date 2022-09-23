// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::kernelrpc::*;
use super::FileIO;
use crate::arch::rackscale::controller::get_local_pid;

pub(crate) fn rpc_getinfo<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    name: P,
) -> Result<(u64, u64), RPCError> {
    debug!("GetInfo({:?})", name);

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            pid,
            KernelRpc::GetInfo as RPCType,
            &[name.as_ref()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("GetInfo() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for getinfo() RPCs in the controller
pub(crate) fn handle_getinfo(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();
    let path_str = core::str::from_utf8(&payload[0..hdr.msg_len as usize])?;
    let path = TryString::try_from(path_str)?.into(); // TODO(alloc): fixme unnecessary

    // Call local file_info function
    let ret = cnrfs::MlnrKernelNode::file_info(local_pid, path);
    // Construct results from return data
    let res = KernelRpcRes {
        ret: convert_return(ret),
    };
    construct_ret(hdr, payload, res)
}
