// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, info, warn};

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::system::MachineId;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::{KError, KResult};
use crate::fs::cnrfs::MlnrKernelNode;
use crate::fs::{cnrfs, NrLock};
use crate::memory::VAddr;
use crate::nr;
use crate::nr::KernelNode;

use super::super::controller_state::ControllerState;
use super::super::dcm::resource_alloc::dcm_resource_alloc;
use super::super::kernelrpc::*;
use super::super::processops::core_work::CoreWorkRes;

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
) -> KResult<(u64, u64)> {
    info!(
        "RequestCore({:?}, {:?})",
        *crate::environment::MACHINE_ID,
        entry_point
    );

    // Construct request data
    let req = RequestCoreReq {
        pid,
        machine_id: *crate::environment::MACHINE_ID,
        entry_point,
    };
    let mut req_data = [0u8; core::mem::size_of::<RequestCoreReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode core request");

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    rpc_client.call(
        KernelRpc::RequestCore as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        info!("RequestCore() {:?}", res);
        *res
    } else {
        Err(KError::from(RPCError::MalformedResponse))
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
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
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
        log::info!(
            "Found unused thread: machine={:?}, gtid={:?}",
            kpi::system::mid_from_gtid(gtid),
            kpi::system::mtid_from_gtid(gtid)
        );

        // can handle request locally if same node otherwise must queue for remote node to handle
        if kpi::system::mid_from_gtid(gtid) != core_req.machine_id {
            log::info!(
                "Logged unfulfilled core assignment for hardware_id={:?}, dcm_node_id={:?}",
                kpi::system::mid_from_gtid(gtid),
                dcm_node_id
            );
            let res = CoreWorkRes {
                pid: core_req.pid,
                gtid: gtid,
                entry_point: core_req.entry_point,
            };
            client_state.core_assignments.push_back(res);
        }
        gtid
    };

    // Construct and return result
    construct_ret(hdr, payload, Ok((gtid as u64, 0)));
    Ok(state)
}
