// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, info, warn};

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::cmdline::MachineId;
use crate::error::KError;
use crate::fs::cnrfs::MlnrKernelNode;
use crate::fs::{cnrfs, NrLock};
use crate::memory::VAddr;
use crate::nr;
use crate::nr::KernelNode;

use super::super::client::get_machine_id;
use super::super::controller_state::ControllerState;
use super::super::dcm::resource_alloc::dcm_resource_alloc;
use super::super::kernelrpc::*;
use super::super::processops::core_work::CoreWorkRes;
use super::super::systemops::{gtid_to_local, local_to_gtid};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestCoreReq {
    pub pid: usize,
    pub machine_id: MachineId,
    pub entry_point: u64,
}
unsafe_abomonate!(RequestCoreReq: pid, machine_id, entry_point);

pub(crate) fn rpc_request_core(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    entry_point: u64,
) -> Result<(u64, u64), RPCError> {
    let machine_id = get_machine_id();
    info!("RequestCore({:?}, {:?})", machine_id, entry_point);

    // Construct request data
    let req = RequestCoreReq {
        pid,
        machine_id,
        entry_point,
    };
    let mut req_data = [0u8; core::mem::size_of::<RequestCoreReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            KernelRpc::RequestCore as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        info!("RequestCore() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_request_core(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::trace!("handle_request_core() start");

    // Parse request
    let core_req = match unsafe { decode::<RequestCoreReq>(payload) } {
        Some((req, _)) => req,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, RPCError::MalformedRequest);
            return Ok(state);
        }
    };

    let dcm_node_id = dcm_resource_alloc(core_req.pid, true);
    let gtid = {
        let mut client_state = state.get_client_state_by_dcm_node_id(dcm_node_id).lock();

        // TODO(performance): controller chooses a core id - right now, sequentially for cores on the dcm_node_id.
        // it should really choose in a NUMA-aware fashion for the remote node.
        let mut gtid = None;
        for i in 0..client_state.hw_threads.len() {
            match client_state.hw_threads[i] {
                (thread, false) => {
                    gtid = Some(thread.id);
                    client_state.hw_threads[i] = (thread, true);
                    break;
                }
                _ => continue,
            }
        }
        // gtid should always be found, as DCM should know if there are free threads or not.
        let gtid = gtid.expect("Failed to find free thread??");
        log::info!("Found unused thread: {:?}", gtid);

        // can handle request locally if same node otherwise must queue for remote node to handle
        if client_state.machine_id != core_req.machine_id {
            log::info!(
                "Logged unfulfilled core assignment for hardware_id={:?}, dcm_node_id={:?}",
                client_state.machine_id,
                dcm_node_id
            );
            let res = CoreWorkRes {
                pid: core_req.pid,
                gtid: gtid as u64,
                entry_point: core_req.entry_point,
            };
            client_state.core_assignments.push_back(res);
        }
        gtid
    };

    // Construct and return result
    let res = KernelRpcRes {
        ret: convert_return(Ok((gtid as u64, 0))),
    };

    construct_ret(hdr, payload, res);
    Ok(state)
}
