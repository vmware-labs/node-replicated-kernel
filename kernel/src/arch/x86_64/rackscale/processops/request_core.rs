// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, info, warn};

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::KError;
use crate::fs::cnrfs::MlnrKernelNode;
use crate::fs::{cnrfs, NrLock};
use crate::memory::VAddr;
use crate::nr;
use crate::nr::KernelNode;

use super::super::client::{get_local_client_id, get_num_clients};
use super::super::controller::{
    get_local_pid, HWTHREADS, HWTHREADS_BUSY, UNFULFILLED_CORE_ASSIGNMENTS,
};
use super::super::dcm::resource_alloc::dcm_resource_alloc;
use super::super::kernelrpc::*;
use super::super::systemops::{gtid_to_local, local_to_gtid};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestCoreReq {
    pub core_id: u64,
    pub entry_point: u64,
}
unsafe_abomonate!(RequestCoreReq: entry_point);

#[derive(Debug)]
pub(crate) struct RequestCoreWorkRes {
    pub work: Option<RequestCoreReq>,
}
unsafe_abomonate!(RequestCoreWorkRes: work);

pub(crate) fn rpc_request_core(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    core_id: u64,
    entry_point: u64,
) -> Result<(u64, u64), RPCError> {
    info!("RequestCore({:?}, {:?})", core_id, entry_point);

    // Construct request data
    let req = RequestCoreReq {
        core_id,
        entry_point,
    };
    let mut req_data = [0u8; core::mem::size_of::<RequestCoreReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            pid,
            KernelRpc::RequestCore as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        info!("RequestCore() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_request_core(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();
    log::trace!("handle_request_core() start");

    // Parse request
    let core_req = match unsafe { decode::<RequestCoreReq>(payload) } {
        Some((req, _)) => req,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let client_id = dcm_resource_alloc(local_pid, true);

    // controller chooses a core id - right now, sequentially for cores on the client_id.
    let num_clients = get_num_clients();
    let mut rack_hwthreads_busy = HWTHREADS_BUSY.lock();
    let mut index = 0;
    loop {
        //
        match rack_hwthreads_busy[local_to_gtid(index, client_id)] {
            // thread is busy, keep looking
            Some(true) => index += 1,
            // found an empty thread! set to busy and break
            Some(false) => {
                rack_hwthreads_busy[index] = Some(true);
                break;
            }
            // Ran out of threads for client; DCM should not have allowed this to happen
            None => panic!(
                "Should never happen - no empty hwthreads found for client {:?}",
                client_id
            ),
        }
    }

    let rack_hwthreads = HWTHREADS.lock();
    let gtid = rack_hwthreads[index].id;
    log::info!("Chose thread id {:?} for request", gtid);

    // Construct and return result
    let res = KernelRpcRes {
        ret: convert_return(Ok((gtid as u64, 0))),
    };

    // can handle request locally if same node otherwise must queue for remote node to handle
    if client_id != hdr.client_id {
        log::info!("Logged unfulfilled core assignment for {:?}", client_id);
        let mut core_request_vec = UNFULFILLED_CORE_ASSIGNMENTS.lock();
        let mut deque = core_request_vec
            .get_mut(client_id as usize)
            .expect("failed to fetch core assignment deque for client_id");
        deque.push_back(*core_req);
    }
    construct_ret(hdr, payload, res)
}

pub(crate) fn request_core_work(rpc_client: &mut dyn RPCClient) -> () {
    let mut pid = 0; // TODO: we will need some way to associate with request with a global pid

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<RequestCoreWorkRes>()];
    rpc_client
        .call(
            pid,
            KernelRpc::RequestWork as RPCType,
            &[],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<RequestCoreWorkRes>(&mut res_data) } {
        if remaining.len() > 0 {
            log::error!("Client got malformed RequestCoreRequest from Controller: Extra data")
            // TODO: maybe panic? Ignore for now
        }
        if let Some(core_request) = res.work {
            log::info!("Client fetched RequestCore() {:?}", core_request);

            // TODO: would be nice to use request_core impl (e.g., like what the controller would use)
            // But not sure if we can do that here because 1) client syscalls are ferried to the controller
            // and 2) how do you run it in the context of the (correct) remote process?
            // for now, copied & modified code from original syscall impl
            let gtid: usize = gtid_to_local(
                core_request.core_id.try_into().unwrap(),
                get_local_client_id(),
            );
            let mut affinity = None;
            for thread in atopology::MACHINE_TOPOLOGY.threads() {
                if thread.id == gtid {
                    affinity = Some(thread.node_id.unwrap_or(0));
                }
            }
            let affinity = affinity
                .ok_or(KError::InvalidGlobalThreadId)
                .expect("Failed to get global thread id (affinity)");

            // TODO: some of this is something that will eventually be moved to the controller.
            // TODO: when moved, will need to (maybe) do address space translation for entry point? Should be done in controller.
            let _gtid = KernelNode::allocate_core_to_process(
                crate::arch::process::current_pid().expect("Cannot get current pid?"), // TODO: set to whatever current pid is executing
                VAddr::from(core_request.entry_point),
                Some(affinity),
                Some(gtid),
            )
            .expect("Failed to allocate core to process");

            log::info!("Client finished processing core work request");
        } else {
            log::trace!("Client received no work.")
        }
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_request_core_work(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
) -> Result<(), RPCError> {
    let work = {
        let mut core_request_vec = UNFULFILLED_CORE_ASSIGNMENTS.lock();
        let mut deque = core_request_vec
            .get_mut(hdr.client_id as usize)
            .expect("failed to fetch core assignment deque for node");
        deque.pop_front()
    };
    if work.is_some() {
        log::info!("handle_request_core_work() Found work={:?}", work);
    }
    let result = RequestCoreWorkRes { work };

    // Populate output buffer & header
    unsafe { encode(&result, &mut payload) }.unwrap();
    hdr.msg_len = core::mem::size_of::<RequestCoreWorkRes>() as u64;

    Ok(())
}
