// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::system::MachineId;
use rpc::rpc::*;

use super::super::controller_state::CONTROLLER_STATE;
use super::super::dcm::resource_alloc::dcm_resource_alloc;
use super::super::kernelrpc::*;
use crate::arch::rackscale::CLIENT_STATE;
use crate::error::{KError, KResult};
use crate::memory::VAddr;
use crate::nr::KernelNode;
use crate::process::Pid;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestCoreReq {
    pub pid: Pid,
    pub new_pid: bool,
    pub entry_point: u64,
}
unsafe_abomonate!(RequestCoreReq: pid, new_pid, entry_point);

pub(crate) fn rpc_request_core(pid: Pid, new_pid: bool, entry_point: u64) -> KResult<(u64, u64)> {
    log::debug!("RequestCore({:?}, {:?}, {:?})", pid, new_pid, entry_point);

    // Construct request data
    let req = RequestCoreReq {
        pid,
        new_pid,
        entry_point,
    };
    let mut req_data = [0u8; core::mem::size_of::<RequestCoreReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode core request");

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::RequestCore as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        log::debug!("RequestCore() {:?}", res);
        *res
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_request_core(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    log::debug!("handle_request_core() start");

    // Parse request
    let core_req = match unsafe { decode::<RequestCoreReq>(payload) } {
        Some((req, _)) => req,
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };

    let (mids, _) = dcm_resource_alloc(core_req.pid, 1, 0);
    let mid = mids[0];

    let (gtid, gtid_affinity) = CONTROLLER_STATE
        .claim_hardware_thread(mid)
        .expect("Failed to find free thread?");

    log::debug!(
        "Found unused thread: machine={:?}, gtid={:?} node={:?}",
        kpi::system::mid_from_gtid(gtid),
        kpi::system::mtid_from_gtid(gtid),
        gtid_affinity,
    );

    let ret = KernelNode::allocate_core_to_process(
        core_req.pid,
        VAddr(core_req.entry_point),
        Some(gtid_affinity),
        Some(gtid),
    );

    match ret {
        Ok(_) => {
            if core_req.new_pid {
                crate::fs::cnrfs::MlnrKernelNode::add_process(core_req.pid)
                    .expect("TODO(rackscale, error-handling): revert state");
            }
            construct_ret(hdr, payload, Ok((gtid as u64, 0)));
        }
        Err(err) => {
            construct_error_ret(hdr, payload, err);
        }
    }

    // Construct and return result
    Ok(())
}
