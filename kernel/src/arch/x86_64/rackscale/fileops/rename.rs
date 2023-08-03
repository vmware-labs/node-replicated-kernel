// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::{String, ToString};
use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use rpc::rpc::*;

use super::super::fileops::get_str_from_payload;
use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use super::FileIO;
use crate::error::{KError, KResult};
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

#[derive(Debug)]
pub(crate) struct RenameReq {
    pub pid: usize,
    pub oldname_len: u64,
}
unsafe_abomonate!(RenameReq: pid, oldname_len);

pub(crate) fn rpc_rename<P: AsRef<[u8]> + Debug>(
    pid: usize,
    oldname: P,
    newname: P,
) -> KResult<(u64, u64)> {
    log::debug!("Rename({:?}, {:?})", oldname, newname);

    // Construct request data
    let req = RenameReq {
        pid,
        oldname_len: oldname.as_ref().len() as u64,
    };
    let mut req_data = [0u8; core::mem::size_of::<RenameReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call the RPC
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::FileRename as RPCType,
        &[&req_data, oldname.as_ref(), newname.as_ref()],
        &mut [&mut res_data],
    )?;

    // Parse and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        log::debug!("Rename() {:?}", res);
        *res
    } else {
        log::error!("Rename(): Malformed response");
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for rename() RPCs in the controller
pub(crate) fn handle_rename(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode request
    let (pid, oldname_len) = match unsafe { decode::<RenameReq>(payload) } {
        Some((req, _)) => (req.pid, req.oldname_len as usize),
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };

    let oldname = get_str_from_payload(
        payload,
        core::mem::size_of::<RenameReq>(),
        core::mem::size_of::<RenameReq>() + oldname_len,
    );
    let newname = get_str_from_payload(
        payload,
        (core::mem::size_of::<RenameReq>() + oldname_len),
        hdr.msg_len as usize,
    );

    match (oldname, newname) {
        (Ok(oldname_str), Ok(newname_str)) => construct_ret(
            hdr,
            payload,
            cnrfs::MlnrKernelNode::file_rename(pid, oldname_str, newname_str),
        ),
        (Err(e), _) => construct_error_ret(hdr, payload, KError::from(e)),
        (_, Err(e)) => construct_error_ret(hdr, payload, KError::from(e)),
    }
    Ok(())
}
