// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;
use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::io::FileModes;

use rpc::rpc::*;

use super::super::fileops::get_str_from_payload;
use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use super::FileIO;
use crate::error::{KError, KResult};
use crate::fallible_string::TryString;
use crate::fs::cnrfs;

#[derive(Debug)]
pub(crate) struct MkDirReq {
    pub pid: usize,
    pub modes: FileModes,
}
unsafe_abomonate!(MkDirReq: pid, modes);

pub(crate) fn rpc_mkdir<P: AsRef<[u8]> + Debug>(
    pid: usize,
    pathname: P,
    modes: FileModes,
) -> KResult<(u64, u64)> {
    log::debug!("MkDir({:?})", pathname);

    // Construct request data
    let req = MkDirReq { pid, modes };
    let mut req_data = [0u8; core::mem::size_of::<MkDirReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode mkdir request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call RPC
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::MkDir as RPCType,
        &[&req_data, pathname.as_ref()],
        &mut [&mut res_data],
    )?;

    // Parse and return result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            log::debug!("MkDir() {:?}", res);
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for close() RPCs in the controller
pub(crate) fn handle_mkdir(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Parse request
    let (pid, modes) = match unsafe { decode::<MkDirReq>(payload) } {
        Some((req, _)) => (req.pid, req.modes),
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };

    let ret = get_str_from_payload(
        payload,
        core::mem::size_of::<MkDirReq>(),
        hdr.msg_len as usize,
    )
    .and_then(|path_string| cnrfs::MlnrKernelNode::mkdir(pid, path_string, modes));

    // Call mkdir function and send result
    construct_ret(hdr, payload, ret);
    Ok(())
}
