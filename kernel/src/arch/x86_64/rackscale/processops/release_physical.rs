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
use crate::arch::rackscale::client::get_frame_as;
use crate::arch::rackscale::controller::{get_local_pid, SHMEM_MANAGERS};
use crate::transport::shmem::SHMEM_REGION;

#[derive(Debug)]
pub(crate) struct ReleasePhysicalReq {
    pub frame_base: u64,
    pub frame_size: u64,
    pub node_id: u64,
}
unsafe_abomonate!(ReleasePhysicalReq: frame_base, frame_size, node_id);

/// RPC to forward physical memory release to controller.
pub(crate) fn rpc_release_physical(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    frame_id: u64,
) -> Result<(u64, u64), RPCError> {
    info!("ReleasePhysical({:?})", frame_id);

    // Construct request data
    let node_id = get_frame_as(frame_id)?;

    // TODO - need to be able to lookup frame?
    //let frame = NrProcess::<Ring3Process>::lookup_frame_for_process(pid, fid)?;
    let frame_base = 0; // TODO: should be frame.base;
    let frame_size = 0; // TODO: should be frame.size;

    let req = ReleasePhysicalReq {
        frame_base,
        frame_size,
        node_id,
    };
    let mut req_data = [0u8; core::mem::size_of::<ReleasePhysicalReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            pid,
            KernelRpc::ReleasePhysical as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }

        if let Ok((0, 0)) = res.ret {
            // TODO: Disassociate frame with the local process
            //NrProcess::<Ring3Process>::release_frame_from_process(pid, fid)?;
            return Ok((0, 0));
        } else {
            return res.ret;
        }
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

/// RPC handler for releasing physical memory on the controller.
pub(crate) fn handle_release_physical(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Extract data needed from the request
    let frame_base;
    let frame_size;
    let node_id;
    if let Some((req, _)) = unsafe { decode::<ReleasePhysicalReq>(payload) } {
        debug!(
            "AllocPhysical(frame_base={:x?}, frame_size={:?}), node_id={:?}",
            req.frame_base, req.frame_size, req.node_id
        );
        frame_base = req.frame_base;
        frame_size = req.frame_size;
        node_id = req.node_id;
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    // TODO: update DCM
    //let node = make_dcm_request(local_pid, false);
    //debug!("Received node assignment from DCM: node {:?}", node);

    // TODO: using dummy affinity
    let frame = Frame::new(PAddr::from(frame_base), frame_size as usize, 0);

    let mut shmem_managers = SHMEM_MANAGERS.lock();
    // TODO: here and in alloc should percolate error to client
    let manager = shmem_managers[node_id as usize]
        .as_mut()
        .expect("Error - no shmem manager found for client");
    let ret = if frame_size <= BASE_PAGE_SIZE as u64 {
        manager.release_base_page(frame)
    } else {
        manager.release_large_page(frame)
    };

    let res = match ret {
        Ok(()) => KernelRpcRes {
            ret: convert_return(Ok((0, 0))),
        },
        Err(kerror) => {
            debug!("Failed to release physical frame: {:?}", kerror);
            KernelRpcRes {
                ret: convert_return(Err(kerror)),
            }
        }
    };
    construct_ret(hdr, payload, res)
}
