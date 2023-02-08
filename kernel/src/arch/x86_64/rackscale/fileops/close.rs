// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::RPCClient;

use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;

use super::super::controller_state::ControllerState;
use super::super::kernelrpc::*;
use super::FileIO;

#[derive(Debug)]
pub(crate) struct CloseReq {
    pub pid: usize,
    pub fd: FileDescriptor,
}
unsafe_abomonate!(CloseReq: pid, fd);

pub(crate) fn rpc_close(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
) -> Result<(u64, u64), RPCError> {
    // Setup request data
    let req = CloseReq { pid, fd };
    let mut req_data = [0u8; core::mem::size_of::<CloseReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Setup result
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call Close() RPC
    rpc_client
        .call(
            KernelRpc::Close as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        // Check for extra data
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }

        debug!("Close() {:?}", res);
        return res.ret;

    // Report malformed data if failed to decode result
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for close() RPCs in the controller
pub(crate) fn handle_close(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    // Decode request
    if let Some((req, _)) = unsafe { decode::<CloseReq>(payload) } {
        debug!("Close(pid={:?}), fd={:?}", req.pid, req.fd);

        // Call close (unmap_fd) and return result
        let res = KernelRpcRes {
            ret: convert_return(cnrfs::MlnrKernelNode::unmap_fd(req.pid, req.fd)),
        };
        construct_ret(hdr, payload, res);

    // Report error if failed to decode request
    } else {
        warn!("Invalid payload for request {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }
    Ok(state)
}
