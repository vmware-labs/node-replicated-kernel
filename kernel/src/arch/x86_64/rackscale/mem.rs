// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, info, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;

use super::fio::*;

#[derive(Debug)]
pub(crate) struct MemReq {
    pub size: u64,
    pub affinity: u64,
}
unsafe_abomonate!(MemReq: size, affinity);

/// RPC to forward physical memory allocation request to controller.
pub(crate) fn rpc_alloc_physical(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    size: u64,
    affinity: u64,
) -> Result<(u64, u64), RPCError> {
    info!("AllocPhysical({:?}, {:?})", size, affinity);

    // Construct request data
    let req = MemReq { size, affinity };
    let mut req_data = [0u8; core::mem::size_of::<MemReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call readat() or read() RPCs
    rpc_client
        .call(
            pid,
            KernelRpc::AllocPhysical as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        info!("AllocPhysical() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

/// RPC handler for physical memory allocation on the controller.
pub(crate) fn handle_phys_alloc(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Extract data needed from the request
    let size;
    let affinity;
    if let Some((req, _)) = unsafe { decode::<MemReq>(payload) } {
        debug!(
            "AllocPhysical(size={:?}, affinity={:?}), local_pid={:?}",
            req.size, req.affinity, local_pid
        );
        size = req.size;
        affinity = req.affinity;
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    // Allocate physical memory
    log::error!(
        "Need to implement allocating physical memory {} {}",
        size,
        affinity
    );
    //let ret = cnrfs::NrProcess::allocate_physical(size, affinity);

    // Construct return
    let res = KernelRpcRes {
        ret: convert_return(Ok((0, 0))),
    };
    construct_ret(hdr, payload, res)
}
