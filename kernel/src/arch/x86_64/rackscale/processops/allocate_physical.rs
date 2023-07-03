// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use atopology::NodeId;
use kpi::system::MachineId;
use kpi::FileOperation;
use rpc::rpc::*;
use rpc::RPCClient;

use super::super::controller_state::{ControllerState, SHMEM_MEMSLICE_ALLOCATORS};
use super::super::dcm::resource_alloc::dcm_resource_alloc;
use super::super::kernelrpc::*;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::CLIENT_STATE;
use crate::error::{KError, KResult};
use crate::fs::fd::FileDescriptor;
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::{Frame, PAddr, BASE_PAGE_SIZE};
use crate::nrproc::NrProcess;
use crate::process::Pid;

#[derive(Debug)]
pub(crate) struct AllocatePhysicalReq {
    pub pid: Pid,
    pub size: u64,
    pub affinity: u64,
}
unsafe_abomonate!(AllocatePhysicalReq: size, affinity);

/// RPC to forward physical memory allocation request to controller.
pub(crate) fn rpc_allocate_physical(pid: Pid, size: u64, affinity: u64) -> KResult<(u64, u64)> {
    log::debug!("AllocatePhysical({:?}, {:?})", size, affinity);

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
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::AllocatePhysical as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }

        if let Ok((frame_affinity, frame_base)) = res {
            // Associate frame with the local process
            let frame = Frame::new(
                PAddr::from(*frame_base),
                size as usize,
                *frame_affinity as NodeId,
            );
            let fid = NrProcess::<Ring3Process>::allocate_frame_to_process(pid, frame)?;

            log::debug!("AllocatePhysical() done");
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
        log::debug!(
            "AllocatePhysical(size={:x?}, affinity={:?}), pid={:?}",
            req.size,
            req.affinity,
            req.pid
        );
        size = req.size;
        affinity = req.affinity;
        pid = req.pid;
    } else {
        log::error!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
        return Ok(state);
    }

    // Let DCM choose node
    let (_, dcm_node_ids) = dcm_resource_alloc(pid, 0, 1);
    let dcm_node_id = dcm_node_ids[0];
    log::debug!("Received node assignment from DCM: node {:?}", dcm_node_id);

    // TODO(error_handling): should handle errors gracefully here, maybe percolate to client?
    let frame = {
        let mid = state.dcm_id_to_mid(dcm_node_id);
        let mut shmem_managers = SHMEM_MEMSLICE_ALLOCATORS.lock();
        let mut manager = &mut shmem_managers[mid as usize - 1];
        manager
            .allocate_large_page()
            .expect("DCM should ensure we have a frame to allocate here.")
    };

    construct_ret(
        hdr,
        payload,
        Ok((frame.affinity as u64, frame.base.as_u64())),
    );
    Ok(state)
}
