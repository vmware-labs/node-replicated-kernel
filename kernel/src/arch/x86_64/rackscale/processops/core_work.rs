// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, info, warn};

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::system::{GlobalThreadId, MachineId};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::KError;
use crate::memory::VAddr;
use crate::nr;
use crate::nr::KernelNode;

use super::super::controller_state::ControllerState;
use super::super::kernelrpc::*;

#[derive(Debug)]
pub(crate) struct CoreWorkReq {
    pub machine_id: MachineId,
}
unsafe_abomonate!(CoreWorkReq: machine_id);

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoreWorkRes {
    pub pid: usize,
    pub gtid: GlobalThreadId,
    pub entry_point: u64,
}
unsafe_abomonate!(CoreWorkRes: pid, gtid, entry_point);

#[derive(Debug)]
pub(crate) struct MaybeCoreWorkRes {
    pub work: Option<CoreWorkRes>,
}
unsafe_abomonate!(MaybeCoreWorkRes: work);

pub(crate) fn rpc_core_work(rpc_client: &mut dyn RPCClient) -> () {
    debug!("CoreWork()");

    // Construct request data
    let req = CoreWorkReq {
        machine_id: *crate::environment::MACHINE_ID,
    };
    let mut req_data = [0u8; core::mem::size_of::<CoreWorkReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode core work request");

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<MaybeCoreWorkRes>()];
    rpc_client
        .call(
            KernelRpc::RequestWork as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .expect("Failed to send core work result request to controller");

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<MaybeCoreWorkRes>(&mut res_data) } {
        if remaining.len() > 0 {
            // TODO(error_handling): ignoring for now but should perhaps panic or ignore message?
            log::error!("Client got malformed MaybeCoreWorkRes from Controller: Extra data")
        }
        if let Some(core_request) = res.work {
            log::info!("Client fetched RequestCore() {:?}", core_request);
            debug_assert!(
                kpi::system::mid_from_gtid(core_request.gtid) == *crate::environment::MACHINE_ID
            );

            let mut affinity = None;
            for thread in atopology::MACHINE_TOPOLOGY.threads() {
                if thread.id == kpi::system::mtid_from_gtid(core_request.gtid) {
                    affinity = Some(thread.node_id.unwrap_or(0));
                }
            }
            let affinity = affinity
                .ok_or(KError::InvalidGlobalThreadId)
                .expect("Failed to get thread affinity");

            let _mtid = KernelNode::allocate_core_to_process(
                core_request.pid,
                VAddr::from(core_request.entry_point),
                Some(affinity),
                Some(core_request.gtid),
            )
            .expect("Failed to allocate core to process");

            log::info!("Client finished processing core work request");
        } else {
            log::trace!("Client received no work.")
        }
    }
}

// Handler function for rpc_core_work() RPCs
pub(crate) fn handle_core_work(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::trace!("handle_core_work() start");

    // Parse request
    let machine_id = match unsafe { decode::<CoreWorkReq>(payload) } {
        Some((work_req, _)) => work_req.machine_id,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(state);
        }
    };

    let work = {
        let mut client_state = state.get_client_state_by_machine_id(machine_id).lock();
        client_state.core_assignments.pop_front()
    };
    if work.is_some() {
        log::info!("handle_core_work() Found work={:?}", work);
    }
    let result = MaybeCoreWorkRes { work };

    // Populate output buffer & header
    unsafe { encode(&result, &mut payload) }.expect("Failed to encode core work result");
    hdr.msg_len = core::mem::size_of::<MaybeCoreWorkRes>() as u64;
    Ok(state)
}
