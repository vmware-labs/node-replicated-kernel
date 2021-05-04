// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;

use fringe::Stack;

/// Default stack size in bytes.
pub const DEFAULT_STACK_SIZE_BYTES: usize = 32 * 4096;

/// LineupStack holds a non-guarded, heap-allocated stack.
#[derive(Debug, PartialEq)]
pub struct LineupStack {
    base_ptr: *mut u8,
    layout: Layout,
    dealloc: bool,
}

impl Default for LineupStack {
    fn default() -> Self {
        LineupStack::from_size(DEFAULT_STACK_SIZE_BYTES)
    }
}

impl LineupStack {
    /// Allocates a new stack with `size` accessible bytes and alignment appropriate
    /// for the current platform using the default Rust allocator.
    pub fn from_size(size: usize) -> LineupStack {
        unsafe {
            let aligned_size = size & !(fringe::STACK_ALIGNMENT - 1);
            let layout = Layout::from_size_align_unchecked(aligned_size, fringe::STACK_ALIGNMENT);

            let base_ptr = alloc(layout);
            assert!(!base_ptr.is_null());

            LineupStack {
                base_ptr,
                layout,
                dealloc: true,
            }
        }
    }

    pub fn from_ptr(base_ptr: *mut u8, size: usize, dealloc: bool) -> LineupStack {
        unsafe {
            let aligned_size = size & !(fringe::STACK_ALIGNMENT - 1);
            assert!(aligned_size == size, "Provided size is aligned");
            let layout = Layout::from_size_align_unchecked(aligned_size, fringe::STACK_ALIGNMENT);

            LineupStack {
                base_ptr,
                layout,
                dealloc,
            }
        }
    }
}

impl Drop for LineupStack {
    fn drop(&mut self) {
        if self.dealloc {
            unsafe { dealloc(self.base_ptr, self.layout) }
        }
    }
}

unsafe impl Stack for LineupStack {
    #[inline(always)]
    fn base(&self) -> *mut u8 {
        // The slice cannot wrap around the address space, so the conversion from usize
        // to isize will not wrap either.
        let len = self.layout.size() as isize;
        unsafe { self.limit().offset(len) }
    }

    #[inline(always)]
    fn limit(&self) -> *mut u8 {
        self.base_ptr
    }
}
