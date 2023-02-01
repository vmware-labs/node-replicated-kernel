// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use super::super::controller_state::ControllerState;
use super::super::kernelrpc::*;
use crate::arch::serial::SerialControl;
use crate::error::{KError, KResult};
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

pub(crate) fn rpc_log<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    msg: P,
) -> Result<(u64, u64), KError> {
    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    rpc_client.call(
        KernelRpc::Log as RPCType,
        &[msg.as_ref()],
        &mut [&mut res_data],
    )?;

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            debug!("Log() {:?}", res);
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for getinfo() RPCs in the controller
pub(crate) fn handle_log(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    match core::str::from_utf8(&payload[0..hdr.msg_len as usize]) {
        Ok(msg_str) => log::info!("Remote Log: {}", msg_str),
        Err(e) => log::warn!(
            "log: invalid UTF-8 string: {:?}",
            &payload[0..hdr.msg_len as usize]
        ),
    }

    // Construct results from return data
    construct_ret(hdr, payload, Ok((0, 0)));
    Ok(state)
}
