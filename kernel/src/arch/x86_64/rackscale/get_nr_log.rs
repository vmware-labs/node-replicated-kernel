// Copyright © 2023 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use abomonation::{decode, encode};
use alloc::sync::Arc;
//use core::fmt::Debug;
//use core2::io::Result as IOResult;
//use core2::io::Write;

use node_replication::{Log, Replica};
use rpc::rpc::*;
use rpc::RPCClient;

use super::controller_state::ControllerState;
use super::kernelrpc::*;
use crate::arch::kcb::per_core_mem;
use crate::error::{KError, KResult};
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, SHARED_AFFINITY};
use crate::nr::{Op, NR_LOG};

// This isn't truly a syscall
pub(crate) fn rpc_get_nr_log(rpc_client: &mut dyn RPCClient) -> KResult<Arc<Log<'static, Op>>> {
    // Construct result buffer and call RPC
    log::debug!("Calling GetNrLog()");
    let mut res_data = [0u8; core::mem::size_of::<u64>()];
    rpc_client
        .call(KernelRpc::GetNrLog as RPCType, &[], &mut [&mut res_data])
        .unwrap();

    // Decode and return the result
    if let Some((ret, remaining)) = unsafe { decode::<u64>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(RPCError::ExtraData.into())
        } else {
            let log_ptr = paddr_to_kernel_vaddr(PAddr::from(*ret));
            let local_log_arc =
                unsafe { Arc::from_raw(log_ptr.as_u64() as *const Log<'static, Op>) };
            Ok(local_log_arc.clone())
        }
    } else {
        Err(RPCError::MalformedResponse.into())
    }
}

// RPC Handler function for rpc_get_nr_log() in the controller
pub(crate) fn handle_get_nr_log(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::debug!("Handling get_nr_log()");

    // We want to allocate clones of the log arcs in shared memory
    let original_affinity = {
        let pcm = per_core_mem();
        let affinity = pcm.physical_memory.borrow().affinity;
        pcm.set_mem_affinity(SHARED_AFFINITY)
            .expect("Can't change affinity");
        affinity
    };

    // Create a clone in shared memory, and get the raw representation of it
    // The clone increments the strong counter, and the into_raw consumes this clone of the arc.
    let log_clone = Arc::into_raw(Arc::clone(&NR_LOG));

    // Send the raw pointer to the client clone address
    // To do this, we'll convert the kernel address to a physical address, and then change it to a shmem offset by subtracting the shmem base.
    // TODO(hunhoffe): try to simplify this
    let log_paddr = kernel_vaddr_to_paddr(VAddr::from_u64((*&log_clone as *const Log<Op>) as u64));

    // Reset mem allocator to use per core memory again
    {
        let pcm = per_core_mem();
        pcm.set_mem_affinity(original_affinity)
            .expect("Can't change affinity");
    }

    // Modify header and write into output buffer
    unsafe { encode(&(log_paddr.as_u64()), &mut payload) }.unwrap();
    hdr.msg_len = core::mem::size_of::<u64>() as u64;
    Ok(state)
}
