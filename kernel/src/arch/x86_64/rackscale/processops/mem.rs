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
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::{Frame, PAddr, BASE_PAGE_SIZE};
use crate::nrproc::NrProcess;

use super::super::dcm::dcm_request::make_dcm_request;
use super::super::dcm::DCM_INTERFACE;
use super::super::kernelrpc::*;
use crate::arch::process::current_pid;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::controller::get_local_pid;
use crate::transport::shmem::SHMEM_REGION;

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

        if let Ok((frame_size, frame_base)) = res.ret {
            // Associate frame with the local process
            info!(
                "AllocPhysical() mapping base from {:?} to {:?}",
                frame_base,
                frame_base + SHMEM_REGION.base_addr
            );
            let frame = Frame::new(
                PAddr::from(frame_base) + SHMEM_REGION.base_addr,
                frame_size as usize,
                affinity as usize,
            );
            let fid = NrProcess::<Ring3Process>::allocate_frame_to_process(pid, frame)?;

            return Ok((fid as u64, frame_base));
        } else {
            return res.ret;
        }
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

/// RPC handler for physical memory allocation on the controller.
pub(crate) fn handle_phys_alloc(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
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

    // Let DCM choose node
    let _node = make_dcm_request(local_pid, false);
    debug!("Received node assignment from DCM");

    // TODO: right now only one allocator, so DCM decision isn't actually used.
    // TODO: how should affinity be handled? Should be this be an NR operation on the controller?
    let mut dcm = DCM_INTERFACE.lock();
    let ret = if size <= BASE_PAGE_SIZE as u64 {
        dcm.shmem_manager.allocate_base_page()
    } else {
        dcm.shmem_manager.allocate_large_page()
    };

    let res = match ret {
        Ok(frame) => {
            debug!("Shmem Frame: {:?}", frame);
            KernelRpcRes {
                // TODO: Should be Ok((fid as u64, frame.base.as_u64()))
                ret: convert_return(Ok((frame.size as u64, frame.base.as_u64()))),
            }
        }
        Err(kerror) => {
            debug!("Failed to allocate physical frame: {:?}", kerror);
            KernelRpcRes {
                ret: convert_return(Err(kerror)),
            }
        }
    };
    construct_ret(hdr, payload, res)
}
