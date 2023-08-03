// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use fallible_collections::FallibleVecGlobal;

use kpi::system::CpuThread;
use rpc::rpc::*;

use super::super::controller_state::CONTROLLER_STATE;
use super::super::kernelrpc::*;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::CLIENT_STATE;
use crate::error::{KError, KResult};
use crate::nrproc::NrProcess;
use crate::process::{UVAddr, UserSlice};

pub(crate) fn rpc_get_hardware_threads(
    pid: usize,
    vaddr_buf: u64,
    vaddr_buf_len: u64,
) -> KResult<(u64, u64)> {
    log::debug!("GetHardwareThreads()");

    // Setup result
    // TODO: make dynamic, for now, size copied from kpi implementation
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>() + 5 * 4096];

    // Call GetHardwareThreads() RPC
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::GetHardwareThreads as RPCType,
        &[&[]],
        &mut [&mut res_data],
    )?;

    // Decode and return result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if let Ok((data_len, n)) = res {
            if *data_len as usize <= remaining.len() && *data_len <= vaddr_buf_len {
                let mut user_slice =
                    UserSlice::new(pid, UVAddr::try_from(vaddr_buf)?, *data_len as usize)?;
                NrProcess::<Ring3Process>::write_to_userspace(
                    &mut user_slice,
                    &remaining[..*data_len as usize],
                )?;
                log::debug!("GetHardwareThreads() = {:?}", res);
                Ok((*data_len, *n))
            } else {
                log::error!(
                    "Bad payload data: data_len: {:?} remaining.len(): {:?} vaddr_buf_len: {:?}",
                    *data_len,
                    remaining.len(),
                    vaddr_buf_len
                );
                Err(KError::from(RPCError::MalformedResponse))
            }
        } else {
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for get_hardware_threads() RPCs in the controller
pub(crate) fn handle_get_hardware_threads(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
) -> Result<(), RPCError> {
    // Encode hwthread information into payload buffer
    let hw_threads = CONTROLLER_STATE.get_hardware_threads();
    let start = KernelRpcRes_SIZE as usize;
    let end = start
        + hw_threads.len() * core::mem::size_of::<CpuThread>()
        + core::mem::size_of::<Vec<CpuThread>>();
    let additional_data = end - start;
    unsafe { encode(&hw_threads, &mut &mut payload[start..end]) }
        .expect("Failed to encode hardware thread vector");
    log::debug!(
        "Sending back {:?} bytes of data ({:?} hwthreads)",
        additional_data,
        hw_threads.len()
    );

    // Construct return
    construct_ret_extra_data(
        hdr,
        payload,
        Ok((additional_data as u64, 0)),
        additional_data as u64,
    );
    Ok(())
}
