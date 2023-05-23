// Copyright © 2023 University of Colorado and VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A stub of a memory provider that queries DCM for memory. If it fails,
//! it should cause the replica to drop (eventually)

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::alloc::{AllocError, Allocator};
use core::ptr::NonNull;

use crate::arch::kcb::per_core_mem;
use crate::memory::SHARED_AFFINITY;
use crate::transport::shmem::is_shmem_addr;

//use crate::arch::kcb::per_core_mem;
//use crate::memory::per_core::SHARED_AFFINITY;

#[derive(Clone)]
pub(crate) struct ShmemAlloc();

unsafe impl Allocator for ShmemAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        log::trace!("ShmemAlloc - allocating");
        let affinity = {
            // We want to allocate the logs in shared memory
            let pcm = per_core_mem();
            let affinity = pcm.physical_memory.borrow().affinity;
            pcm.set_mem_affinity(SHARED_AFFINITY)
                .expect("Can't change affinity");
            affinity
        };

        let ptr = unsafe { alloc(layout) };

        let ret = if !ptr.is_null() {
            // TODO(rackscale performance): should probably be debug_assert
            assert!(
                is_shmem_addr(ptr as u64, true, true),
                "allocated pointer ({}) isn't a shmem address",
                ptr as u64,
            );

            Ok(unsafe {
                let nptr = NonNull::new_unchecked(ptr);
                NonNull::slice_from_raw_parts(nptr, layout.size())
            })
        } else {
            Err(AllocError)
        };

        // Return to previous affinity
        let pcm = per_core_mem();
        pcm.set_mem_affinity(affinity)
            .expect("Can't change affinity");

        log::trace!("ShmemAlloc - allocating finished.");
        ret
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // TODO(rackscale performance): should probably be debug_assert
        assert!(is_shmem_addr(ptr.as_ptr() as u64, true, true));

        let affinity = {
            // We want to allocate the logs in shared memory
            let pcm = per_core_mem();
            let affinity = pcm.physical_memory.borrow().affinity;
            pcm.set_mem_affinity(SHARED_AFFINITY)
                .expect("Can't change affinity");
            affinity
        };

        // dealloc just goes to the underlying allocator
        dealloc(ptr.as_ptr(), layout);

        // Return to previous affinity
        let pcm = per_core_mem();
        pcm.set_mem_affinity(affinity)
            .expect("Can't change affinity");
    }
}
