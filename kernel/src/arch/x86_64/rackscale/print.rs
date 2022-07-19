// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::fio::*;

pub(crate) fn rpc_log<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    msg: P,
) -> Result<(u64, u64), RPCError> {
    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    rpc_client
        .call(
            pid,
            LwkRpc::Log as RPCType,
            &[msg.as_ref()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
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
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }

    let local_pid = local_pid.unwrap();
    let msg_str = core::str::from_utf8(&payload[0..hdr.msg_len as usize])?;
    log::info!("Remote Log from {}: {}", local_pid, msg_str);

    // Construct results from return data
    let res = FIORes {
        ret: convert_return(Ok((0, 0))),
    };
    construct_ret(hdr, payload, res)
}
