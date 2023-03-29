// Copyright © 2023 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use abomonation::{decode, encode};
use alloc::sync::Arc;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use crossbeam_queue::ArrayQueue;

use rpc::rpc::*;
use rpc::RPCClient;

use super::controller_state::ControllerState;
use super::kernelrpc::*;
use crate::arch::kcb::per_core_mem;
use crate::arch::tlb::{Shootdown, RACKSCALE_CLIENT_WORKQUEUES};
use crate::error::KResult;
use crate::memory::vspace::TlbFlushHandle;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, SHARED_AFFINITY};

// This isn't truly a syscall
pub(crate) fn rpc_get_workqueues(
    rpc_client: &mut dyn RPCClient,
) -> KResult<Arc<Vec<ArrayQueue<(Arc<Shootdown>, TlbFlushHandle)>>>> {
    // Construct result buffer and call RPC
    log::debug!("Calling GetWorkqueues()");

    let mut res_data = [0u8; core::mem::size_of::<u64>()];
    rpc_client
        .call(
            KernelRpc::GetWorkqueues as RPCType,
            &[],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((ret, remaining)) = unsafe { decode::<u64>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData.into());
        }
        let queue_ptr = paddr_to_kernel_vaddr(PAddr::from(*ret));
        let local_workqueue_arc = unsafe {
            Arc::from_raw(
                queue_ptr.as_u64() as *const Vec<ArrayQueue<(Arc<Shootdown>, TlbFlushHandle)>>
            )
        };
        return Ok(local_workqueue_arc);
    } else {
        Err(RPCError::MalformedResponse.into())
    }
}

// RPC Handler function for rpc_get_workqueues() in the controller
pub(crate) fn handle_get_workqueues(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    log::debug!("Handling get_workqueues()");

    // We want to allocate clones of the workqueue arcs in shared memory
    let original_affinity = {
        let pcm = per_core_mem();
        let affinity = pcm.physical_memory.borrow().affinity;
        pcm.set_mem_affinity(SHARED_AFFINITY)
            .expect("Can't change affinity");
        affinity
    };

    // Create a clone in shared memory, and get the raw representation of it
    // The clone increments the strong counter, and the into_raw consumes this clone of the arc.
    let client_workqueue_clone = Arc::into_raw(Arc::clone(&RACKSCALE_CLIENT_WORKQUEUES));

    // Send the raw pointer to the client clone address
    // To do this, we'll convert the kernel address to a physical address, and then change it to a shmem offset by subtracting the shmem base.
    // TODO(hunhoffe): try to simplify this
    let arc_workqueue_paddr = kernel_vaddr_to_paddr(VAddr::from_u64(
        (*&client_workqueue_clone as *const Vec<ArrayQueue<(Arc<Shootdown>, TlbFlushHandle)>>)
            as u64,
    ));

    // Reset mem allocator to use original per core memory affinity again
    {
        let pcm = per_core_mem();
        pcm.set_mem_affinity(original_affinity)
            .expect("Can't change affinity");
    }

    // Modify header and write into output buffer
    unsafe { encode(&arc_workqueue_paddr.as_u64(), &mut payload) }.unwrap();
    hdr.msg_len = core::mem::size_of::<u64>() as u64;

    Ok(state)
}
