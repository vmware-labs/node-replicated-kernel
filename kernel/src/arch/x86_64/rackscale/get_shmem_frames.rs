// Copyright © 2023 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core2::io::Result as IOResult;
use core2::io::Write;
use fallible_collections::FallibleVecGlobal;

use kpi::system::MachineId;
use rpc::rpc::*;
use rpc::RPCClient;

use super::client_state::CLIENT_STATE;
use super::controller_state::ControllerState;
use super::dcm::{affinity_alloc::dcm_affinity_alloc, resource_alloc::dcm_resource_alloc};
use super::kernelrpc::*;
use crate::error::{KError, KResult};
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::Frame;
use crate::process::Pid;
use crate::transport::shmem::ShmemRegion;

use crate::memory::backends::AllocatorStatistics;

struct ShmemFrameReq {
    machine_id: Option<MachineId>,
    pid: Option<Pid>,
    num_frames: usize,
}
unsafe_abomonate!(ShmemFrameReq: machine_id, pid, num_frames);

// This isn't truly a syscall
pub(crate) fn rpc_get_shmem_frames(
    pid: Option<Pid>,
    num_frames: usize,
) -> KResult<Box<Vec<Frame>>> {
    assert!(num_frames > 0);
    log::debug!("GetShmemFrames({:?})", num_frames);

    let machine_id = if pid.is_none() {
        Some(*crate::environment::MACHINE_ID)
    } else {
        None
    };

    let req = ShmemFrameReq {
        machine_id,
        pid,
        num_frames,
    };

    let mut req_data = [0u8; core::mem::size_of::<ShmemFrameReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode shmem frame request");

    let max_res_size = core::mem::size_of::<KResult<(u64, u64)>>()
        + num_frames * core::mem::size_of::<ShmemRegion>()
        + core::mem::size_of::<Vec<ShmemRegion>>();
    let mut res_data = Vec::try_with_capacity(max_res_size)
        .expect("Not enough memory to create vec to receive data");
    for i in 0..max_res_size {
        res_data.push(0u8);
    }
    CLIENT_STATE
        .rpc_client
        .lock()
        .call(
            KernelRpc::GetShmemFrames as RPCType,
            &[&req_data],
            &mut [&mut res_data[..]],
        )
        .unwrap();

    // Decode and return the result
    if let Some((ret, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        // Check KResult
        match ret {
            Ok(_) => {
                // Construct frames from remaining data
                let mut frames = Box::new(Vec::<Frame>::new());
                if let Some((regions, remaining)) = unsafe { decode::<Vec<ShmemRegion>>(remaining) }
                {
                    if remaining.len() > 0 {
                        log::error!("Extra data after parsing all shmem regions");
                        return Err(RPCError::MalformedResponse.into());
                    }
                    for i in 0..num_frames {
                        let frame = regions[i].get_frame(0);
                        frames.push(frame);
                    }
                } else {
                    log::error!("Failed to parse shmem region response from controller");
                    return Err(RPCError::MalformedRequest.into());
                }
                log::debug!("GetShmemFrames({:?}) finished", num_frames);
                Ok(frames)
            }
            Err(e) => Err(*e),
        }
    } else {
        Err(RPCError::MalformedResponse.into())
    }
}

// RPC Handler function for rpc_get_shmem_frames() in the controller
pub(crate) fn handle_get_shmem_frames(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::debug!("Handling get_shmem_frames()");

    // Parse request
    let (machine_id, pid, num_frames) = match unsafe { decode::<ShmemFrameReq>(payload) } {
        Some((req, _)) => (req.machine_id, req.pid, req.num_frames),
        None => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(state);
        }
    };

    let mut regions = Vec::<ShmemRegion>::new();

    if let Some(mid) = machine_id {
        // Ask DCM to make sure we can safely take from the local allocators
        let node_id = state.mid_to_dcm_id(mid);
        // TODO: if it fails, ask for memory from somewhere else??
        if !dcm_affinity_alloc(node_id, num_frames) {
            log::error!("GetShmemFrames failed due to lack of memory");
            construct_error_ret(hdr, payload, KError::DCMNotEnoughMemory);
            return Ok(state);
        }

        // Take the frames from the local allocator
        {
            let mut client_state = state.get_client_state_by_dcm_id(node_id).lock();
            let mut manager = client_state
                .shmem_manager
                .as_mut()
                .expect("No shmem manager found for client");

            for _i in 0..num_frames {
                let frame = manager
                    .allocate_large_page()
                    .expect("DCM OK'd allocation, this should succeed");
                regions.push(ShmemRegion {
                    base: frame.base.as_u64(),
                    size: frame.size as u64,
                });
            }
        }
    } else if let Some(pid) = pid {
        // Let DCM choose node
        let (_, dcm_ids) = dcm_resource_alloc(pid, 0, num_frames as u64);
        for i in 0..num_frames {
            let dcm_id = dcm_ids[i];
            log::debug!("Received node assignment from DCM: node {:?}", dcm_id);

            // TODO(error_handling): should handle errors gracefully here, maybe percolate to client?
            let mut client_state = state.get_client_state_by_dcm_id(dcm_id).lock();
            let mut manager = client_state
                .shmem_manager
                .as_mut()
                .expect("No shmem manager found for client");
            let frame = manager
                .allocate_large_page()
                .expect("DCM OK'd allocation, this should succeed");
            regions.push(ShmemRegion {
                base: frame.base.as_u64(),
                size: frame.size as u64,
            });
        }
    } else {
        log::error!("Malformed request: must specify either pid or machine id");
        construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
        return Ok(state);
    }

    let start = core::mem::size_of::<KResult<((u64, u64))>>() as usize;
    let end = start
        + num_frames * core::mem::size_of::<ShmemRegion>()
        + core::mem::size_of::<Vec<ShmemRegion>>();
    let additional_data = end - start;
    unsafe { encode(&regions, &mut &mut payload[start..end]) }
        .expect("Failed to encode shmem region vector");
    log::debug!(
        "Sending back {:?} bytes of data ({:?} frames)",
        additional_data,
        regions.len()
    );

    // Construct return
    construct_ret_extra_data(hdr, payload, Ok((0, 0)), additional_data as u64);
    Ok(state)
}
