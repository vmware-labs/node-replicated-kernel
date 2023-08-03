// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use kpi::io::{FileFlags, FileModes};
use rpc::rpc::*;

use super::super::fileops::get_str_from_payload;
use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use super::FileIO;
use crate::error::{KError, KResult};
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

#[derive(Debug)]
pub(crate) struct OpenReq {
    pub pid: usize,
    pub flags: FileFlags,
    pub modes: FileModes,
}
unsafe_abomonate!(OpenReq: pid, flags, modes);

// This is just a wrapper function for rpc_open_create
pub(crate) fn rpc_open<P: AsRef<[u8]> + Debug>(
    pid: usize,
    pathname: P,
    flags: FileFlags,
    modes: FileModes,
) -> KResult<(u64, u64)> {
    rpc_open_create(pid, pathname, flags, modes, KernelRpc::Open as RPCType)
}

fn rpc_open_create<P: AsRef<[u8]> + Debug>(
    pid: usize,
    pathname: P,
    flags: FileFlags,
    modes: FileModes,
    rpc_type: RPCType,
) -> KResult<(u64, u64)> {
    log::debug!("Open({:?}, {:?}, {:?})", pathname, flags, modes);

    // Construct request data
    let req = OpenReq { pid, flags, modes };
    let mut req_data = [0u8; core::mem::size_of::<OpenReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode open request");

    // Construct result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call the RPC
    CLIENT_STATE.rpc_client.lock().call(
        rpc_type,
        &[&req_data, pathname.as_ref()],
        &mut [&mut res_data],
    )?;

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        log::debug!("Open() {:?}", res);
        *res
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for open() RPCs in the controller
pub(crate) fn handle_open(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode request
    let (pid, flags, modes) = match unsafe { decode::<OpenReq>(payload) } {
        Some((req, _)) => {
            log::debug!(
                "Open(flags={:?}, modes={:?}), pid={:?}",
                FileFlags::from(req.flags),
                FileModes::from(req.modes),
                req.pid
            );
            (req.pid, req.flags, req.modes)
        }
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };

    let ret = get_str_from_payload(
        payload,
        core::mem::size_of::<OpenReq>(),
        hdr.msg_len as usize,
    )
    .and_then(|path_string| cnrfs::MlnrKernelNode::map_fd(pid, path_string, flags, modes));

    construct_ret(hdr, payload, ret);
    Ok(())
}
