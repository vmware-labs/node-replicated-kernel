// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::arch::process::current_pid;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::client_state::CLIENT_STATE;
use crate::error::{KError, KResult};
use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::{Frame, PAddr, BASE_PAGE_SIZE};
use crate::nrproc::NrProcess;
use crate::transport::shmem::{ShmemRegion, SHMEM_DEVICE};

use super::super::controller_state::ControllerState;
use super::super::dcm::resource_alloc::dcm_resource_alloc;
use super::super::dcm::DCM_INTERFACE;
use super::super::kernelrpc::*;

#[derive(Debug)]
pub(crate) struct AllocatePhysicalReq {
    pub pid: usize,
    pub size: u64,
    pub affinity: u64,
}
unsafe_abomonate!(AllocatePhysicalReq: size, affinity);

/// RPC to forward physical memory allocation request to controller.
pub(crate) fn rpc_allocate_physical(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    size: u64,
    affinity: u64,
) -> KResult<(u64, u64)> {
    debug!("AllocatePhysical({:?}, {:?})", size, affinity);

    // Construct request data
    let req = AllocatePhysicalReq {
        pid,
        size,
        affinity,
    };
    let mut req_data = [0u8; core::mem::size_of::<AllocatePhysicalReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode allocate physical request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    rpc_client.call(
        KernelRpc::AllocatePhysical as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }

        if let Ok((node_id, frame_base)) = res {
            // Associate frame with the local process
            let shmem_region = ShmemRegion {
                base: *frame_base,
                size,
            };
            let frame = shmem_region.get_frame(SHMEM_DEVICE.region.base);
            debug!(
                "AllocatePhysical() mapping base from {:x?} to {:?}",
                *frame_base, frame,
            );
            let fid = NrProcess::<Ring3Process>::allocate_frame_to_process(pid, frame)?;

            // Add frame mapping to client map
            CLIENT_STATE.add_frame(fid, *node_id);

            return Ok((fid as u64, *frame_base));
        } else {
            return *res;
        }
    } else {
        return Err(KError::from(RPCError::MalformedResponse));
    }
}

/// RPC handler for physical memory allocation on the controller.
pub(crate) fn handle_allocate_physical(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    // Extract data needed from the request
    let size;
    let affinity;
    let pid;
    if let Some((req, _)) = unsafe { decode::<AllocatePhysicalReq>(payload) } {
        debug!(
            "AllocatePhysical(size={:x?}, affinity={:?}), pid={:?}",
            req.size, req.affinity, req.pid
        );
        size = req.size;
        affinity = req.affinity;
        pid = req.pid;
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
        return Ok(state);
    }

    // Let DCM choose node
    let dcm_node_id = dcm_resource_alloc(pid, false);
    debug!("Received node assignment from DCM: node {:?}", dcm_node_id);

    // TODO(error_handling): should handle errors gracefully here, maybe percolate to client?
    let ret = {
        let mut client_state = state.get_client_state_by_dcm_node_id(dcm_node_id).lock();
        let mut manager = client_state
            .shmem_manager
            .as_mut()
            .expect("No shmem manager found for client");

        if size <= BASE_PAGE_SIZE as u64 {
            manager.allocate_base_page()
        } else {
            manager.allocate_large_page()
        }
    };

    let res = match ret {
        Ok(frame) => {
            debug!("Shmem Frame: {:?}", frame);
            // Should technically be Ok((fid as u64, frame.base.as_u64()))
            // We return node_id here, but it should really be an AS (address space)
            // identifier, (most likely). This works for now because there is only
            // 1 AS per node.
            Ok((dcm_node_id, frame.base.as_u64()))
        }
        Err(kerror) => {
            debug!("Failed to allocate physical frame: {:?}", kerror);
            Err(kerror)
        }
    };
    construct_ret(hdr, payload, res);
    Ok(state)
}
