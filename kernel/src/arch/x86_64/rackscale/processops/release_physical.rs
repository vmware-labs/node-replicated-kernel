// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::process::FrameId;
use kpi::FileOperation;
use log::{debug, error, info, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::{KError, KResult};
use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::{Frame, PAddr, BASE_PAGE_SIZE, SHARED_AFFINITY};
use crate::nrproc::NrProcess;

use super::super::client_state::CLIENT_STATE;
use super::super::controller_state::ControllerState;
use super::super::dcm::resource_release::dcm_resource_release;
use super::super::dcm::{DCMNodeId, DCM_INTERFACE};
use super::super::kernelrpc::*;
use crate::arch::process::current_pid;
use crate::arch::process::Ring3Process;
use crate::transport::shmem::SHMEM_DEVICE;

#[derive(Debug)]
pub(crate) struct ReleasePhysicalReq {
    pub pid: usize,
    pub frame_base: u64,
    pub frame_size: u64,
    pub node_id: DCMNodeId,
}
unsafe_abomonate!(ReleasePhysicalReq: frame_base, frame_size, node_id);

/// RPC to forward physical memory release to controller.
pub(crate) fn rpc_release_physical(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    frame_id: u64,
) -> KResult<(u64, u64)> {
    info!("ReleasePhysical({:?})", frame_id);

    // Construct request data
    let node_id = CLIENT_STATE.get_frame_as(frame_id as FrameId)?;

    // TODO(error_handling): will probably want to do this NrProcess operation on controller, so we can't have a state where this
    // succeeds but the next part fails without the controller knowing.
    // this will check if it's removeable (e.g., mapped or no) so we should do this operation before doing anything else
    let frame = NrProcess::<Ring3Process>::release_frame_from_process(pid, frame_id as FrameId)?;
    CLIENT_STATE.remove_frame(frame_id as FrameId)?;

    let req = ReleasePhysicalReq {
        pid,
        frame_base: frame.base.as_u64(),
        frame_size: frame.size as u64,
        node_id,
    };
    let mut req_data = [0u8; core::mem::size_of::<ReleasePhysicalReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode release physical request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    rpc_client.call(
        KernelRpc::ReleasePhysical as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

/// RPC handler for releasing physical memory on the controller.
pub(crate) fn handle_release_physical(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    // Extract data needed from the request
    let req = match unsafe { decode::<ReleasePhysicalReq>(payload) } {
        Some((req, _)) => req,
        _ => {
            warn!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(state);
        }
    };
    debug!(
        "AllocPhysical(frame_base={:x?}, frame_size={:?}), dcm_node_id={:?}",
        req.frame_base, req.frame_size, req.node_id
    );

    let frame = Frame::new(
        PAddr::from(req.frame_base),
        req.frame_size as usize,
        SHARED_AFFINITY,
    );

    // TODO(error_handling): should handle errors gracefully here, maybe percolate to client?
    let ret = {
        let mut client_state = state.get_client_state_by_dcm_node_id(req.node_id).lock();
        let mut manager = client_state
            .shmem_manager
            .as_mut()
            .expect("No shmem manager found for client");

        if req.frame_size <= BASE_PAGE_SIZE as u64 {
            manager.release_base_page(frame)
        } else {
            manager.release_large_page(frame)
        }
    };

    // Construct result. For success, both DCM and the manager need to release the memory
    let res = match ret {
        Ok(()) => {
            // Tell DCM the resource is no longer being used
            if dcm_resource_release(req.node_id, req.pid, false) == 0 {
                debug!("DCM release resource was successful");
                Ok((0, 0))
            } else {
                error!("DCM release resource failed");
                // TODO: not sure if this is the best error to send
                Err(KError::DCMError)
            }
        }
        Err(kerror) => {
            error!("Manager failed to release physical frame: {:?}", kerror);
            Err(kerror)
        }
    };
    construct_ret(hdr, payload, res);
    Ok(state)
}
