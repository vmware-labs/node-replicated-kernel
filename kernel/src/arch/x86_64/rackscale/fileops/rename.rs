// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;
use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, error, warn};

use rpc::rpc::*;
use rpc::RPCClient;

use super::super::kernelrpc::*;
use super::FileIO;
use crate::arch::rackscale::controller::get_local_pid;
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

#[derive(Debug)]
pub(crate) struct RenameReq {
    pub oldname_len: u64,
}
unsafe_abomonate!(RenameReq: oldname_len);

pub(crate) fn rpc_rename<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    oldname: P,
    newname: P,
) -> Result<(u64, u64), RPCError> {
    debug!("Rename({:?}, {:?})", oldname, newname);

    // Construct request data
    let req = RenameReq {
        oldname_len: oldname.as_ref().len() as u64,
    };
    let mut req_data = [0u8; core::mem::size_of::<RenameReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call the RPC
    rpc_client
        .call(
            pid,
            KernelRpc::FileRename as RPCType,
            &[&req_data, oldname.as_ref(), newname.as_ref()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Parse and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Rename() {:?}", res);
        res.ret
    } else {
        error!("Rename(): Malformed response");
        Err(RPCError::MalformedResponse)
    }
}

// RPC Handler function for rename() RPCs in the controller
pub(crate) fn handle_rename(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Decode request
    let oldname_len = match unsafe { decode::<RenameReq>(payload) } {
        Some((req, _)) => req.oldname_len as usize,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let oldname_str = core::str::from_utf8(
        &payload
            [core::mem::size_of::<RenameReq>()..(core::mem::size_of::<RenameReq>() + oldname_len)],
    )?;
    let oldname = TryString::try_from(oldname_str)?.into();

    let newname_str = core::str::from_utf8(
        &payload[(core::mem::size_of::<RenameReq>() + oldname_len)..hdr.msg_len as usize],
    )?;
    let newname = TryString::try_from(newname_str)?.into();

    // Call rename function
    let res = KernelRpcRes {
        ret: convert_return(cnrfs::MlnrKernelNode::file_rename(
            local_pid, oldname, newname,
        )),
    };

    // Return result
    construct_ret(hdr, payload, res)
}
