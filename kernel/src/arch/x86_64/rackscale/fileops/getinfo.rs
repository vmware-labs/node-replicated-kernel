// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::kernelrpc::*;
use super::FileIO;

#[derive(Debug)]
pub(crate) struct GetInfoReq {
    pub pid: usize,
}
unsafe_abomonate!(GetInfoReq: pid);

pub(crate) fn rpc_getinfo<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    name: P,
) -> Result<(u64, u64), RPCError> {
    debug!("GetInfo({:?})", name);

    // Construct request data
    let req = GetInfoReq { pid };
    let mut req_data = [0u8; core::mem::size_of::<GetInfoReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            KernelRpc::GetInfo as RPCType,
            &[&req_data, name.as_ref()],
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
    // Parse request
    let pid = match unsafe { decode::<GetInfoReq>(payload) } {
        Some((req, _)) => req.pid,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };
    let path_str = core::str::from_utf8(
        &payload[core::mem::size_of::<GetInfoReq>() as usize..hdr.msg_len as usize],
    )?;
    let path = TryString::try_from(path_str)?.into(); // TODO(hunhoffe): fixme unnecessary
    let ret = cnrfs::MlnrKernelNode::file_info(pid, path);

    // Construct results from return data
    let res = KernelRpcRes {
        ret: convert_return(ret),
    };
    construct_ret(hdr, payload, res)
}
