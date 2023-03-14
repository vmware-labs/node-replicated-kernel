// Copyright © 2023 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::sync::Arc;
use arrayvec::ArrayVec;
use core::fmt::Debug;
use core2::io::Result as IOResult;
use core2::io::Write;

use node_replication::{Dispatch, Log};
use rpc::rpc::*;
use rpc::RPCClient;

use super::controller_state::ControllerState;
use super::kernelrpc::*;
use crate::arch::kcb::per_core_mem;
use crate::arch::process::{Ring3Process, PROCESS_LOGS};
use crate::error::KError;
use crate::fs::cnrfs;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, SHARED_AFFINITY};
use crate::nr;
use crate::nrproc::NrProcess;
use crate::process::MAX_PROCESSES;
use crate::transport::shmem::SHMEM_DEVICE;

struct ProcessLogPtrs {
    logs: [u64; MAX_PROCESSES],
}
unsafe_abomonate!(ProcessLogPtrs: logs);

// This isn't truly a syscall
pub(crate) fn rpc_get_proccess_logs(
    rpc_client: &mut dyn RPCClient,
) -> Result<
    Box<
        ArrayVec<
            Arc<Log<'static, <NrProcess<Ring3Process> as Dispatch>::WriteOperation>>,
            MAX_PROCESSES,
        >,
    >,
    KError,
> {
    // Construct result buffer and call RPC
    log::debug!("Calling GetProcessLogs()");
    let mut res_data = [0u8; core::mem::size_of::<[u64; MAX_PROCESSES]>()];
    rpc_client
        .call(
            KernelRpc::GetProcessLogs as RPCType,
            &[],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((ret, remaining)) = unsafe { decode::<[u64; MAX_PROCESSES]>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData.into());
        }

        let mut logs = Box::new(ArrayVec::new());
        for i in 0..ret.len() {
            let log_ptr = paddr_to_kernel_vaddr(PAddr::from(ret[i] + SHMEM_DEVICE.region.base));
            let local_log_arc = unsafe {
                Arc::from_raw(log_ptr.as_u64()
                    as *const Log<'static, <NrProcess<Ring3Process> as Dispatch>::WriteOperation>)
            };
            logs.push(local_log_arc);
        }

        return Ok(logs);
    } else {
        Err(RPCError::MalformedResponse.into())
    }
}

// RPC Handler function for rpc_get_process_logs() in the controller
pub(crate) fn handle_get_process_logs(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::info!("Handling get_process_logs()");
    let mut logs = [0u64; MAX_PROCESSES];

    // We want to allocate clones of the log arcs in shared memory
    let original_affinity = {
        let pcm = per_core_mem();
        let affinity = pcm.physical_memory.borrow().affinity;
        pcm.set_mem_affinity(SHARED_AFFINITY)
            .expect("Can't change affinity");
        affinity
    };

    for i in 0..PROCESS_LOGS.len() {
        // Create a clone in shared memory, and get the raw representation of it
        // The clone increments the strong counter, and the into_raw consumes this clone of the arc.
        let client_clone = Arc::into_raw(Arc::clone(&PROCESS_LOGS[i]));

        // Send the raw pointer to the client clone address
        // To do this, we'll convert the kernel address to a physical address, and then change it to a shmem offset by subtracting the shmem base.
        // TODO(hunhoffe): try to simplify this
        let arc_log_paddr = kernel_vaddr_to_paddr(VAddr::from_u64(
            (*&client_clone
                as *const Log<'static, <NrProcess<Ring3Process> as Dispatch>::WriteOperation>)
                as u64,
        ));
        logs[i] = arc_log_paddr.as_u64() - SHMEM_DEVICE.region.base;
    }

    // Reset mem allocator to use per core memory again
    {
        let pcm = per_core_mem();
        pcm.set_mem_affinity(original_affinity)
            .expect("Can't change affinity");
        log::info!("Finished initializing process logs in shmem");
    }

    // Modify header and write into output buffer
    unsafe { encode(&logs, &mut payload) }.unwrap();
    hdr.msg_len = core::mem::size_of::<[usize; MAX_PROCESSES]>() as u64;
    Ok(state)
}
