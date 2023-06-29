// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use atopology::NodeId;
use kpi::process::FrameId;
use kpi::FileOperation;
use rpc::rpc::*;
use rpc::RPCClient;

use super::super::dcm::resource_release::dcm_resource_release;
use super::super::dcm::DCMNodeId;
use super::super::kernelrpc::*;
use super::super::ControllerState;
use super::super::CLIENT_STATE;
use crate::arch::process::Ring3Process;
use crate::error::{KError, KResult};
use crate::fs::fd::FileDescriptor;
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::shmem_affinity::get_shmem_affinity_index;
use crate::memory::{Frame, PAddr, LARGE_PAGE_SIZE};
use crate::nrproc::NrProcess;
use crate::process::Pid;
use crate::transport::shmem::get_shmem_index_by_addr;

#[derive(Debug)]
pub(crate) struct ReleasePhysicalReq {
    pub pid: Pid,
    // TODO(rackscale): just send the frame.
    pub frame_base: u64,
    pub frame_size: u64,
    pub affinity: NodeId,
}
unsafe_abomonate!(ReleasePhysicalReq: frame_base, frame_size, affinity);

/// RPC to forward physical memory release to controller.
pub(crate) fn rpc_release_physical(pid: Pid, frame_id: u64) -> KResult<(u64, u64)> {
    log::debug!("ReleasePhysical({:?})", frame_id);

    // TODO(rackscale, error_handling): will probably want to do this NrProcess operation on controller,
    // so we can't have a state where this succeeds but the next part fails without the controller knowing.
    let frame = NrProcess::<Ring3Process>::release_frame_from_process(pid, frame_id as FrameId)?;

    let req = ReleasePhysicalReq {
        pid,
        frame_base: frame.base.as_u64(),
        frame_size: frame.size as u64,
        affinity: frame.affinity,
    };
    let mut req_data = [0u8; core::mem::size_of::<ReleasePhysicalReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode release physical request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::ReleasePhysical as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            log::error!("Release physical RPC failed with extra data");
            Err(KError::from(RPCError::ExtraData))
        } else {
            log::debug!("ReleasePhysical({:?}) = {:?}", frame_id, *res);
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
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(state);
        }
    };
    let mid = get_shmem_affinity_index(req.affinity);
    let node_id = state.mid_to_dcm_id(mid);
    log::debug!(
        "ReleasePhysical(frame_base={:x?}, frame_size={:?}), affinity={:?} mid={:?} dcm_node_id={:?}",
        req.frame_base,
        req.frame_size,
        req.affinity,
        mid,
        node_id,
    );

    // we only allocate in large frames, so let's also deallocate in large frames.
    let frame = Frame::new(
        PAddr::from(req.frame_base),
        LARGE_PAGE_SIZE, //req.frame_size as usize,
        req.affinity,
    );

    // TODO(error_handling): should handle errors gracefully here, maybe percolate to client?
    let ret = {
        let mut client_state = state.get_client_state_by_mid(mid).lock();
        let mut manager = client_state.shmem_manager.as_mut();
        manager.release_large_page(frame)
    };

    // Construct result. For success, both DCM and the manager need to release the memory
    let res = match ret {
        Ok(()) => {
            // Tell DCM the resource is no longer being used
            if dcm_resource_release(node_id, req.pid, false) == 0 {
                log::debug!("DCM release resource was successful");
                Ok((0, 0))
            } else {
                log::error!("DCM release resource failed");
                // TODO: not sure if this is the best error to send
                Err(KError::DCMError)
            }
        }
        Err(kerror) => {
            log::error!("Manager failed to release physical frame: {:?}", kerror);
            Err(kerror)
        }
    };
    construct_ret(hdr, payload, res);
    Ok(state)
}
