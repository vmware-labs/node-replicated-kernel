// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fallible_string::TryString;
use crate::fs::cnrfs;

use super::super::kernelrpc::*;
use super::FileIO;

#[derive(Debug)]
pub(crate) struct DeleteReq {
    pub pid: usize,
}
unsafe_abomonate!(DeleteReq: pid);

pub(crate) fn rpc_delete(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    pathname: String,
) -> Result<(u64, u64), RPCError> {
    debug!("Delete({:?})", pathname);

    // Construct request data
    let req = DeleteReq { pid };
    let mut req_data = [0u8; core::mem::size_of::<DeleteReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create buffer for result
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call RPC
    rpc_client
        .call(
            KernelRpc::Delete as RPCType,
            &[&req_data, &pathname.as_bytes()],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode result - return result if decoding successful
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Delete() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_delete(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Parse request
    let pid = match unsafe { decode::<DeleteReq>(payload) } {
        Some((req, _)) => req.pid,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };
    let path = core::str::from_utf8(
        &payload[core::mem::size_of::<DeleteReq>() as usize..hdr.msg_len as usize],
    )?;

    // Construct and return result
    let res = KernelRpcRes {
        ret: convert_return(cnrfs::MlnrKernelNode::file_delete(
            pid,
            TryString::try_from(path)?.into(), // TODO(hunhoffe): unnecessary allocation
        )),
    };
    construct_ret(hdr, payload, res)
}
