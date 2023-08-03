// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use rpc::rpc::*;

use crate::error::{KError, KResult};
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::fileops::get_str_from_payload;
use super::super::kernelrpc::*;
use super::FileIO;
use crate::arch::rackscale::CLIENT_STATE;

#[derive(Debug)]
pub(crate) struct DeleteReq {
    pub pid: usize,
}
unsafe_abomonate!(DeleteReq: pid);

pub(crate) fn rpc_delete(pid: usize, pathname: String) -> KResult<(u64, u64)> {
    log::debug!("Delete({:?})", pathname);

    // Construct request data
    let req = DeleteReq { pid };
    let mut req_data = [0u8; core::mem::size_of::<DeleteReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode delete request");

    // Create buffer for result
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call RPC
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::Delete as RPCType,
        &[&req_data, &pathname.as_bytes()],
        &mut [&mut res_data],
    )?;

    // Decode result - return result if decoding successful
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        log::debug!("Delete() {:?}", res);
        return *res;
    } else {
        return Err(KError::from(RPCError::MalformedResponse));
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_delete(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Parse request
    let pid = match unsafe { decode::<DeleteReq>(payload) } {
        Some((req, _)) => req.pid,
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };

    let ret = get_str_from_payload(
        payload,
        core::mem::size_of::<DeleteReq>(),
        hdr.msg_len as usize,
    )
    .and_then(|path_string| cnrfs::MlnrKernelNode::file_delete(pid, path_string));

    construct_ret(hdr, payload, ret);
    Ok(())
}
