// Copyright © 2023 University of Colorado and VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A stub of a memory provider that queries DCM for memory. If it fails,
//! it should cause the replica to drop (eventually)

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::alloc::{AllocError, Allocator};
use core::ptr::NonNull;

//use crate::arch::kcb::per_core_mem;
//use crate::memory::per_core::SHARED_AFFINITY;

#[derive(Clone)]
pub(crate) struct ShmemAlloc();

unsafe impl Allocator for ShmemAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = unsafe { alloc(layout) };
        if !ptr.is_null() {
            Ok(unsafe {
                let nptr = NonNull::new_unchecked(ptr);
                NonNull::slice_from_raw_parts(nptr, layout.size())
            })
        } else {
            Err(AllocError)
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // dealloc just goes to the underlying allocator
        dealloc(ptr.as_ptr(), layout)
    }
}
