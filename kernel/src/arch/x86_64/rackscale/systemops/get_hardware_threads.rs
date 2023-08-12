// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;

use abomonation::{decode, encode, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use kpi::system::CpuThread;
use rpc::rpc::*;
use rpc::RPCClient;

use super::super::controller_state::CONTROLLER_STATE;
use super::super::kernelrpc::*;
use crate::arch::kcb::per_core_mem;
use crate::arch::process::Ring3Process;
use crate::arch::rackscale::CLIENT_STATE;
use crate::error::{KError, KResult};
use crate::memory::shmem_affinity::local_shmem_affinity;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr};
use crate::nrproc::NrProcess;
use crate::process::{KernArcBuffer, UVAddr, UserSlice};

pub(crate) fn rpc_get_hardware_threads(
    pid: usize,
    vaddr_buf: u64,
    vaddr_buf_len: u64,
) -> KResult<(u64, u64)> {
    log::debug!("GetHardwareThreads()");

    // Setup result
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call GetHardwareThreads() RPC
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::GetHardwareThreads as RPCType,
        &[&[]],
        &mut [&mut res_data],
    )?;

    // Decode and return result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if let Ok((data_len, data_paddr)) = res {
            if remaining.len() == 0 && *data_len <= vaddr_buf_len {
                let arc_arc_paddr = paddr_to_kernel_vaddr(PAddr::from(*data_paddr));
                let mut kab_arc =
                    unsafe { Arc::from_raw(arc_arc_paddr.as_u64() as *const KernArcBuffer) };

                // controller doesn't keep reference, not shared in log yet, so no panic
                let mut kab = Arc::get_mut(&mut kab_arc).unwrap();
                let data = Arc::get_mut(&mut kab.buffer).unwrap();

                let mut user_slice =
                    UserSlice::new(pid, UVAddr::try_from(vaddr_buf)?, *data_len as usize)?;
                NrProcess::<Ring3Process>::write_to_userspace(&mut user_slice, &data)?;
                log::debug!("GetHardwareThreads() = {:?}", res);
                Ok((*data_len, 0))
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
    let data_len = hw_threads.len() * core::mem::size_of::<CpuThread>()
        + core::mem::size_of::<Vec<CpuThread>>();
    log::warn!("Data len is: {:?}", data_len);

    let affinity = {
        // We want to allocate the kernel arc in shared memory
        let pcm = per_core_mem();
        let affinity = pcm.physical_memory.borrow().affinity;
        // Use local shared affinity for now
        pcm.set_mem_affinity(local_shmem_affinity())
            .expect("Can't change affinity");
        affinity
    };

    // TODO: Panics on OOM, need a `try_new_uninit_slice()` https://github.com/rust-lang/rust/issues/63291
    let mut buffer = Arc::<[u8]>::new_uninit_slice(data_len);

    // TODO: this isn't ideal.
    // Safety:
    // - Length == calculated above so that it will initialize next with abomonate encode
    // - It is technically in an uninitialized state until after the call to encode,
    // but abomonate doesn't work on MaybeUninit, so we must pretent it is initialized.
    let mut buffer = unsafe { buffer.assume_init() };
    // this is unsafe state here
    {
        let mut data = Arc::get_mut(&mut buffer).unwrap();
        unsafe { encode(&hw_threads, &mut &mut data) }
            .expect("Failed to encode hardware thread vector");
    }
    // this is safe state again

    let kab_arc = Arc::new(KernArcBuffer { buffer });
    log::warn!("Strong count is: {:?}", Arc::strong_count(&kab_arc));

    #[cfg(feature = "rackscale")]
    {
        // Restore affinity
        if affinity != local_shmem_affinity() {
            let pcm = per_core_mem();
            pcm.set_mem_affinity(affinity)
                .expect("Can't change affinity");
        }
    };

    let arc_arc_ptr = Arc::into_raw(Arc::clone(&kab_arc));
    log::warn!("Strong count is: {:?}", Arc::strong_count(&kab_arc));
    let arc_arc_paddr = kernel_vaddr_to_paddr(VAddr::from_u64(
        (*&arc_arc_ptr as *const KernArcBuffer) as u64,
    ))
    .as_u64();

    // Construct return
    construct_ret(hdr, payload, Ok((data_len as u64, arc_arc_paddr)));
    Ok(())
}
