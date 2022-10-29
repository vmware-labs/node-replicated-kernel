// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, error, info, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::KError;
use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::{Frame, PAddr, BASE_PAGE_SIZE};
use crate::nrproc::NrProcess;

use super::super::dcm::resource_release::dcm_resource_release;
use super::super::dcm::DCM_INTERFACE;
use super::super::kernelrpc::*;
use crate::arch::process::current_pid;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::client::{get_frame_as, FRAME_MAP};
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
    let frame = NrProcess::<Ring3Process>::release_frame_from_process(pid, frame_id as usize)?;

    let mut frame_map = FRAME_MAP.write();
    frame_map
        .remove(&frame_id)
        .expect("Didn't find a frame for frame_id");

    let req = ReleasePhysicalReq {
        frame_base: frame.base.as_u64(),
        frame_size: frame.size as u64,
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

        return res.ret;
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

    // TODO: using dummy affinity
    let frame = Frame::new(PAddr::from(frame_base), frame_size as usize, 0);

    let mut shmem_managers = SHMEM_MANAGERS.lock();

    // TODO: error handling here could use work. Should client be notified?
    let manager = shmem_managers[node_id as usize]
        .as_mut()
        .expect("Error - no shmem manager found for client");

    let ret = if frame_size <= BASE_PAGE_SIZE as u64 {
        manager.release_base_page(frame)
    } else {
        manager.release_large_page(frame)
    };

    // Construct result. For success, both DCM and the manager need to release the memory
    let res = match ret {
        Ok(()) => {
            // Tell DCM the resource is no longer being used
            if dcm_resource_release(node_id, local_pid, false) == 0 {
                debug!("DCM release resource was successful");
                KernelRpcRes {
                    ret: convert_return(Ok((0, 0))),
                }
            } else {
                error!("DCM release resource failed");
                KernelRpcRes {
                    // TODO: not sure if this is the best error to send
                    ret: convert_return(Err(KError::DCMError)),
                }
            }
        }
        Err(kerror) => {
            error!("Manager failed to release physical frame: {:?}", kerror);
            KernelRpcRes {
                ret: convert_return(Err(kerror)),
            }
        }
    };
    construct_ret(hdr, payload, res)
}
