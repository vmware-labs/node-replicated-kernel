// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;
use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::io::FileModes;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::RPCClient;

use super::super::kernelrpc::*;
use super::FileIO;
use crate::arch::rackscale::controller::get_local_pid;
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

#[derive(Debug)]
pub(crate) struct MkDirReq {
    pub modes: FileModes,
}
unsafe_abomonate!(MkDirReq: modes);

pub(crate) fn rpc_mkdir<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    pathname: P,
    modes: FileModes,
) -> Result<(u64, u64), RPCError> {
    debug!("MkDir({:?})", pathname);

    // Construct request data
    let req = MkDirReq { modes };
    let mut req_data = [0u8; core::mem::size_of::<MkDirReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call RPC
    rpc_client
        .call(
            pid,
            KernelRpc::MkDir as RPCType,
            &[&req_data, pathname.as_ref()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Parse and return result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("MkDir() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for close() RPCs in the controller
pub(crate) fn handle_mkdir(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse request
    let modes = match unsafe { decode::<MkDirReq>(payload) } {
        Some((req, _)) => req.modes,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let path =
        core::str::from_utf8(&payload[core::mem::size_of::<MkDirReq>()..hdr.msg_len as usize])?;
    let path_string: String = TryString::try_from(path)?.into();
    let mkdir_req = cnrfs::MlnrKernelNode::mkdir(local_pid, path_string, modes);

    // Call mkdir function and send result
    let res = KernelRpcRes {
        ret: convert_return(mkdir_req),
    };
    construct_ret(hdr, payload, res)
}
