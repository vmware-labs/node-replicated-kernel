// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use fallible_collections::FallibleVecGlobal;

use kpi::system::CpuThread;
use rpc::rpc::*;
use rpc::RPCClient;

use super::super::kernelrpc::*;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::controller::{get_local_pid, HWTHREADS};
use crate::nrproc::NrProcess;
use crate::process::{UVAddr, UserSlice};

pub(crate) fn rpc_get_hardware_threads(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    vaddr_buf: u64,
    vaddr_buf_len: u64,
) -> Result<(u64, u64), RPCError> {
    // Setup result
    // TODO: make dynamic, for now, size copied from kpi implementation
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>() + 5 * 4096];

    // Call GetHardwareThreads() RPC
    rpc_client
        .call(
            pid,
            KernelRpc::GetHardwareThreads as RPCType,
            &[&[]],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        log::info!("GetHardwareThreads() {:?}", res);

        if let Ok((data_len, n)) = res.ret {
            if data_len as usize <= remaining.len() && data_len <= vaddr_buf_len {
                let mut user_slice =
                    UserSlice::new(pid, UVAddr::try_from(vaddr_buf)?, data_len as usize)?;
                NrProcess::<Ring3Process>::write_to_userspace(
                    &mut user_slice,
                    &remaining[..data_len as usize],
                )?;
                Ok((data_len, n))
            } else {
                log::debug!(
                    "Bad payload data: data_len: {:?} remaining.len(): {:?} vaddr_buf_len: {:?}",
                    data_len,
                    remaining.len(),
                    vaddr_buf_len
                );
                Err(RPCError::MalformedResponse)
            }
        } else {
            res.ret
        }
    } else {
        Err(RPCError::MalformedResponse)
    }
}

// RPC Handler function for get_hardware_threads() RPCs in the controller
pub(crate) fn handle_get_hardware_threads(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.client_id, hdr.pid) };
    if local_pid.is_err() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Encode hwthread information into payload buffer
    let rack_threads = HWTHREADS.lock();
    let start = KernelRpcRes_SIZE as usize;
    let end = start
        + rack_threads.len() * core::mem::size_of::<CpuThread>()
        + core::mem::size_of::<Vec<CpuThread>>();
    let additional_data = end - start;
    unsafe { encode(&*rack_threads, &mut &mut payload[start..end]) }
        .expect("Failed to encode hardware thread vector");
    log::trace!(
        "Sending back {:?} bytes of data ({:?} hwthreads)",
        additional_data,
        rack_threads.len()
    );

    // Construct return
    let res = KernelRpcRes {
        ret: Ok((additional_data as u64, 0)),
    };
    construct_ret_extra_data(hdr, payload, res, additional_data as u64)
}
