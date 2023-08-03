// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use rpc::rpc::*;

use crate::error::{KError, KResult};
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::fileops::get_str_from_payload;
use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use super::FileIO;

#[derive(Debug)]
pub(crate) struct GetInfoReq {
    pub pid: usize,
}
unsafe_abomonate!(GetInfoReq: pid);

pub(crate) fn rpc_getinfo<P: AsRef<[u8]> + Debug>(pid: usize, name: P) -> KResult<(u64, u64)> {
    log::debug!("GetInfo({:?})", name);

    // Construct request data
    let req = GetInfoReq { pid };
    let mut req_data = [0u8; core::mem::size_of::<GetInfoReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode getinfo request");

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::GetInfo as RPCType,
        &[&req_data, name.as_ref()],
        &mut [&mut res_data],
    )?;

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            log::debug!("GetInfo() {:?}", res);
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for getinfo() RPCs in the controller
pub(crate) fn handle_getinfo(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Parse request
    let pid = match unsafe { decode::<GetInfoReq>(payload) } {
        Some((req, _)) => req.pid,
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };

    let ret = get_str_from_payload(
        payload,
        core::mem::size_of::<GetInfoReq>(),
        hdr.msg_len as usize,
    )
    .and_then(|path_string| cnrfs::MlnrKernelNode::file_info(pid, path_string));

    // Construct results from return data
    construct_ret(hdr, payload, ret);
    Ok(())
}
