// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::io::{FileFlags, FileModes};
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::kernelrpc::*;
use super::FileIO;
use crate::arch::rackscale::controller::get_local_pid;

#[derive(Debug)]
pub(crate) struct OpenReq {
    pub flags: FileFlags,
    pub modes: FileModes,
}
unsafe_abomonate!(OpenReq: flags, modes);

// This is just a wrapper function for rpc_open_create
pub(crate) fn rpc_open<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    pathname: P,
    flags: FileFlags,
    modes: FileModes,
) -> Result<(u64, u64), RPCError> {
    rpc_open_create(
        rpc_client,
        pid,
        pathname,
        flags,
        modes,
        KernelRpc::Open as RPCType,
    )
}

fn rpc_open_create<P: AsRef<[u8]> + Debug>(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    pathname: P,
    flags: FileFlags,
    modes: FileModes,
    rpc_type: RPCType,
) -> Result<(u64, u64), RPCError> {
    debug!("Open({:?}, {:?}, {:?})", pathname, flags, modes);

    // Construct request data
    let req = OpenReq { flags, modes };
    let mut req_data = [0u8; core::mem::size_of::<OpenReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call the RPC
    rpc_client
        .call(
            pid,
            rpc_type,
            &[&req_data, pathname.as_ref()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Open() {:?}", res);
        res.ret
    } else {
        Err(RPCError::MalformedResponse)
    }
}

// RPC Handler function for open() RPCs in the controller
pub(crate) fn handle_open(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse body
    let flags;
    let modes;
    if let Some((req, _)) =
        unsafe { decode::<OpenReq>(&mut payload[..core::mem::size_of::<OpenReq>()]) }
    {
        debug!(
            "Open(flags={:?}, modes={:?}), local_pid={:?}",
            FileFlags::from(req.flags),
            FileModes::from(req.modes),
            local_pid
        );
        flags = req.flags;
        modes = req.modes;
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    let path =
        core::str::from_utf8(&payload[core::mem::size_of::<OpenReq>()..hdr.msg_len as usize])?;
    let path_string = TryString::try_from(path)?.into();

    let cnr_ret = cnrfs::MlnrKernelNode::map_fd(local_pid, path_string, flags, modes);

    // Create return
    let res = KernelRpcRes {
        ret: convert_return(cnr_ret),
    };
    construct_ret(hdr, payload, res)
}
