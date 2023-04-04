// Copyright © 2023 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::sync::Arc;
//use arrayvec::ArrayVec;
//use core::fmt::Debug;
use core2::io::Result as IOResult;
use core2::io::Write;

use node_replication::{Dispatch, Log};
use rpc::rpc::*;
use rpc::RPCClient;

use super::controller_state::ControllerState;
use super::kernelrpc::*;
use crate::arch::kcb::per_core_mem;
use crate::arch::process::{Ring3Process, PROCESS_LOGS};
use crate::error::{KError, KResult};
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, SHARED_AFFINITY};
use crate::nrproc::NrProcess;
use crate::process::MAX_PROCESSES;

/// Types of shared structures the client can request
#[derive(Clone, Debug, Copy)]
pub enum ShmemStructure {
    /// User-space pointer is not valid
    NrProcLogs,
    NrLog,
}
unsafe_abomonate!(ShmemStructure);

pub(crate) fn rpc_get_shmem_structure(
    rpc_client: &mut dyn RPCClient,
    structure: ShmemStructure,
    ptrs: &mut [u64],
) -> KResult<()> {
    // Construct result buffer and call RPC
    log::debug!("Calling GetShmemStructure({:?})", structure);

    // Encode the request
    let mut req_data = [0u8; core::mem::size_of::<ShmemStructure>()];
    unsafe { encode(&structure, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode shmem structure request");

    let mut res_data = match structure {
        NrProcLogs => [0u8; core::mem::size_of::<[u64; MAX_PROCESSES]>()],
        NrLog => panic!("NYI for this."),
    };

    rpc_client
        .call(
            KernelRpc::GetShmemStructure as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    match structure {
        NrProcLogs => {
            // Decode and return the result
            if let Some((ret, remaining)) = unsafe { decode::<[u64; MAX_PROCESSES]>(&mut res_data) }
            {
                if remaining.len() > 0 {
                    Err(RPCError::ExtraData.into())
                } else {
                    ptrs.clone_from_slice(ret);
                    Ok(())
                }
            } else {
                Err(RPCError::MalformedResponse.into())
            }
        }
        NrLog => panic!("NYI for this."),
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
        NrProcLogs => {
            let mut logs = [0u64; MAX_PROCESSES];

            for i in 0..PROCESS_LOGS.len() {
                // Create a clone in shared memory, and get the raw representation of it
                // The clone increments the strong counter, and the into_raw consumes this clone of the arc.
                let client_clone = Arc::into_raw(Arc::clone(&PROCESS_LOGS[i]));

                // Send the raw pointer to the client clone address
                // To do this, we'll convert the kernel address to a physical address, and then change it to a shmem offset by subtracting the shmem base.
                // TODO(hunhoffe): try to simplify this
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
            hdr.msg_len = core::mem::size_of::<[usize; MAX_PROCESSES]>() as u64;
        }
        NrLog => panic!("NYI for this."),
    }

    // Reset mem allocator to use per core memory again
    {
        let pcm = per_core_mem();
        pcm.set_mem_affinity(original_affinity)
            .expect("Can't change affinity");
    }

    Ok(state)
}
