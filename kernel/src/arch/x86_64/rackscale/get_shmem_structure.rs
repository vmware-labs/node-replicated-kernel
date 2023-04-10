// Copyright © 2023 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;

use crossbeam_queue::ArrayQueue;
use node_replication::{Dispatch, Log};
use rpc::rpc::*;
use rpc::RPCClient;

use super::client_state::CLIENT_STATE;
use super::controller_state::ControllerState;
use super::kernelrpc::*;
use crate::arch::kcb::per_core_mem;
use crate::arch::process::{Ring3Process, PROCESS_LOGS};
use crate::arch::tlb::{Shootdown, RACKSCALE_CLIENT_WORKQUEUES};
use crate::error::{KError, KResult};
use crate::memory::vspace::TlbFlushHandle;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, SHARED_AFFINITY};
use crate::nr::{Op, NR_LOG};
use crate::nrproc::NrProcess;
use crate::process::MAX_PROCESSES;

/// Types of shared structures the client can request
#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub enum ShmemStructure {
    NrProcLogs = 0,
    NrLog = 1,
    WorkQueues = 2,
}
unsafe_abomonate!(ShmemStructure);

pub(crate) fn rpc_get_shmem_structure(
    shmem_structure: ShmemStructure,
    ptrs: &mut [u64],
) -> KResult<()> {
    // Construct result buffer and call RPC
    log::debug!("Calling GetShmemStructure({:?})", shmem_structure);
    let res_size = match shmem_structure {
        ShmemStructure::NrProcLogs => core::mem::size_of::<[u64; MAX_PROCESSES]>(),
        _ => core::mem::size_of::<[u64; 1]>(),
    };

    // Encode the request
    let mut req_data = [0u8; core::mem::size_of::<ShmemStructure>()];
    unsafe { encode(&shmem_structure, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode shmem structure request");

    // Make buffer max size of MAX_PROCESS (for NrProcLogs), 1 (for NrLog)
    let mut res_data = [0u8; core::mem::size_of::<[u64; MAX_PROCESSES]>()];
    CLIENT_STATE
        .rpc_client
        .lock()
        .call(
            KernelRpc::GetShmemStructure as RPCType,
            &[&req_data],
            &mut [&mut res_data[..res_size]],
        )
        .unwrap();

    let decode_result = match shmem_structure {
        ShmemStructure::NrProcLogs => {
            unsafe { decode::<[u64; MAX_PROCESSES]>(&mut res_data[..res_size]) }
                .map(|(ret, remaining)| (&ret[..], remaining.len()))
        }
        _ => unsafe { decode::<[u64; 1]>(&mut res_data[..res_size]) }
            .map(|(ret, remaining)| (&ret[..], remaining.len())),
    };

    // Decode and return the result
    if let Some((ret, remaining)) = decode_result {
        if remaining > 0 {
            Err(RPCError::ExtraData.into())
        } else {
            ptrs.clone_from_slice(&ret);
            Ok(())
        }
    } else {
        Err(RPCError::MalformedResponse.into())
    }
}

// RPC Handler function for rpc_get_shmem_structure() in the controller
pub(crate) fn handle_get_shmem_structure(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::debug!("Handling get_shmem_structure()");

    // Decode request
    let shmem_structure = if let Some((req, _)) = unsafe { decode::<ShmemStructure>(payload) } {
        req
    } else {
        log::warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
        return Ok(state);
    };

    // We want to allocate clones of the log arcs in shared memory
    let original_affinity = {
        let pcm = per_core_mem();
        let affinity = pcm.physical_memory.borrow().affinity;
        pcm.set_mem_affinity(SHARED_AFFINITY)
            .expect("Can't change affinity");
        affinity
    };

    match shmem_structure {
        ShmemStructure::NrProcLogs => {
            let mut logs = [0u64; MAX_PROCESSES];

            for i in 0..PROCESS_LOGS.len() {
                // Create a clone in shared memory, and get the raw representation of it
                // The clone increments the strong counter, and the into_raw consumes this clone of the arc.
                let client_clone = Arc::into_raw(Arc::clone(&PROCESS_LOGS[i]));

                // Send the raw pointer to the client clone address. To do this, we'll convert the kernel address
                // to a physical address, and then change it to a shmem offset by subtracting the shmem base.
                // TODO(rackscale): try to simplify this, and below?
                let arc_log_paddr = kernel_vaddr_to_paddr(VAddr::from_u64(
                    (*&client_clone
                        as *const Log<
                            'static,
                            <NrProcess<Ring3Process> as Dispatch>::WriteOperation,
                        >) as u64,
                ));
                logs[i] = arc_log_paddr.as_u64();
            }

            // Modify header and write into output buffer
            unsafe { encode(&logs, &mut payload) }.unwrap();
            hdr.msg_len = core::mem::size_of::<[u64; MAX_PROCESSES]>() as u64;
        }
        ShmemStructure::NrLog => {
            let log_clone = Arc::into_raw(Arc::clone(&NR_LOG));
            let log_paddr =
                kernel_vaddr_to_paddr(VAddr::from_u64((*&log_clone as *const Log<Op>) as u64))
                    .as_u64();

            // Modify header and write into output buffer
            unsafe { encode(&[log_paddr], &mut payload) }.unwrap();
            hdr.msg_len = core::mem::size_of::<[u64; 1]>() as u64;
        }
        ShmemStructure::WorkQueues => {
            let client_workqueue_clone = Arc::into_raw(Arc::clone(&RACKSCALE_CLIENT_WORKQUEUES));
            let arc_workqueue_paddr = kernel_vaddr_to_paddr(VAddr::from_u64(
                (*&client_workqueue_clone
                    as *const Vec<ArrayQueue<(Arc<Shootdown>, TlbFlushHandle)>>)
                    as u64,
            ))
            .as_u64();

            // Modify header and write into output buffer
            unsafe { encode(&[arc_workqueue_paddr], &mut payload) }.unwrap();
            hdr.msg_len = core::mem::size_of::<[u64; 1]>() as u64;
        }
    }

    // Reset mem allocator to use per core memory again
    {
        let pcm = per_core_mem();
        pcm.set_mem_affinity(original_affinity)
            .expect("Can't change affinity");
    }

    Ok(state)
}
