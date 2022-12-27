// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::kernelrpc::*;

pub(crate) fn rpc_log<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    msg: P,
) -> Result<(u64, u64), RPCError> {
    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            KernelRpc::Log as RPCType,
            &[msg.as_ref()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Log() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for getinfo() RPCs in the controller
pub(crate) fn handle_log(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    let msg_str = core::str::from_utf8(&payload[0..hdr.msg_len as usize])?;
    log::info!("Remote Log: {}", msg_str);

    // Construct results from return data
    let res = KernelRpcRes {
        ret: convert_return(Ok((0, 0))),
    };
    construct_ret(hdr, payload, res)
}
