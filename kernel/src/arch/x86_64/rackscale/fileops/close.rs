// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use rpc::rpc::*;

use crate::error::{KError, KResult};
use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;

use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use super::FileIO;

#[derive(Debug)]
pub(crate) struct CloseReq {
    pub pid: usize,
    pub fd: FileDescriptor,
}
unsafe_abomonate!(CloseReq: pid, fd);

pub(crate) fn rpc_close(pid: usize, fd: FileDescriptor) -> KResult<(u64, u64)> {
    log::debug!("Close({:?})", fd);

    // Setup request data
    let req = CloseReq { pid, fd };
    let mut req_data = [0u8; core::mem::size_of::<CloseReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode close request");

    // Setup result
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call Close() RPC
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::Close as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode and return result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        // Check for extra data
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            log::debug!("Close() {:?}", res);
            *res
        }

    // Report malformed data if failed to decode result
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for close() RPCs in the controller
pub(crate) fn handle_close(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode request
    let ret = if let Some((req, _)) = unsafe { decode::<CloseReq>(payload) } {
        log::debug!("Close(pid={:?}), fd={:?}", req.pid, req.fd);
        cnrfs::MlnrKernelNode::unmap_fd(req.pid, req.fd)
    // Report error if failed to decode request
    } else {
        Err(KError::from(RPCError::MalformedRequest))
    };
    construct_ret(hdr, payload, ret);
    Ok(())
}
