// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © edef <edef@edef.eu>
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Initial inspiration taken from https://github.com/edef1c/libfringe/blob/master/src/stack/mod.rs

//! A series of different stacks that implement the `Stack` trait

use alloc::alloc::alloc;
use alloc::boxed::Box;

use core::alloc::Layout;
use core::slice;

use crate::arch::memory::BASE_PAGE_SIZE;

pub(crate) const STACK_ALIGNMENT: usize = 16;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StackPointer(*mut usize);

/// A trait for objects that hold ownership of a stack.
///
/// To preserve memory safety, an implementation of this trait must fulfill the
/// following contract:
///
///   * The base address of the stack must be aligned to a
///     [`STACK_ALIGNMENT`][align]-byte boundary.
///   * Every address between the base and the limit must be readable and
///     writable.
///
/// # Safety
/// Ideally only hardware/CPU writes to this memory, and all we ever do is
/// program it with `base`?
pub unsafe trait Stack {
    /// Returns the base address of the stack.
    /// On all modern architectures, the stack grows downwards,
    /// so this is the highest address.
    fn base(&self) -> *mut u8;
    /// Returns the limit address of the stack.
    /// On all modern architectures, the stack grows downwards,
    /// so this is the lowest address.
    fn limit(&self) -> *mut u8;
}

/// StaticStack that holds a non-guarded stack of 32 pages.
///
/// Useful during early initialization where memory allocation is not yet available.
pub(crate) struct StaticStack(pub [u8; 32 * BASE_PAGE_SIZE]);

unsafe impl Stack for StaticStack {
    #[inline(always)]
    fn base(&self) -> *mut u8 {
        let ptr = self.0.as_ptr() as usize;
        let adjusted_ptr = (ptr + STACK_ALIGNMENT - 1) & !(STACK_ALIGNMENT - 1);
        let offset = adjusted_ptr - ptr;
        if offset > self.0.len() {
            panic!("StaticStack too small");
        }

        let adjusted_len = (self.0.len() - offset) & !(STACK_ALIGNMENT - 1);
        unsafe { self.limit().add(adjusted_len) }
    }

    #[inline(always)]
    fn limit(&self) -> *mut u8 {
        let ptr = self.0.as_ptr() as usize;
        let adjusted_ptr = (ptr + STACK_ALIGNMENT - 1) & !(STACK_ALIGNMENT - 1);

        adjusted_ptr as *mut u8
    }
}

/// SliceStack holds a non-guarded stack allocated elsewhere and provided as a mutable slice.
#[derive(Debug)]
pub(crate) struct SliceStack<'a>(&'a mut [u8]);

impl<'a> SliceStack<'a> {
    /// Creates a `SliceStack` from an existing slice.
    ///
    /// This function will automatically align the slice to make it suitable for
    /// use as a stack. However this function may panic if the slice is smaller
    /// than `STACK_ALIGNMENT`.
    #[allow(unused)]
    pub(crate) fn new(slice: &'a mut [u8]) -> SliceStack<'a> {
        // Align the given slice so that it matches platform requirements
        let ptr = slice.as_ptr() as usize;
        let adjusted_ptr = (ptr + STACK_ALIGNMENT - 1) & !(STACK_ALIGNMENT - 1);
        let offset = adjusted_ptr - ptr;
        if offset > slice.len() {
            panic!("SliceStack too small");
        }

        let adjusted_len = (slice.len() - offset) & !(STACK_ALIGNMENT - 1);
        SliceStack(&mut slice[offset..(offset + adjusted_len)])
    }
}

unsafe impl<'a> Stack for SliceStack<'a> {
    #[inline(always)]
    fn base(&self) -> *mut u8 {
        // The slice cannot wrap around the address space, so the conversion from usize
        // to isize will not wrap either.
        let len = self.0.len() as isize;
        unsafe { self.limit().offset(len) }
    }

    #[inline(always)]
    fn limit(&self) -> *mut u8 {
        self.0.as_ptr() as *mut u8
    }
}

/// OwnedStack holds a non-guarded, heap-allocated stack.
#[derive(Debug)]
pub(crate) struct OwnedStack(Box<[u8]>);

impl OwnedStack {
    /// Allocates a new stack with exactly `size` accessible bytes and alignment appropriate
    /// for the current platform using the default Rust allocator.
    pub(crate) fn new(size: usize) -> OwnedStack {
        unsafe {
            let aligned_size = size & !(STACK_ALIGNMENT - 1);
            let ptr = alloc(Layout::from_size_align_unchecked(
                aligned_size,
                STACK_ALIGNMENT,
            ));
            OwnedStack(Box::from_raw(slice::from_raw_parts_mut(ptr, aligned_size)))
        }
    }
}

unsafe impl Stack for OwnedStack {
    #[inline(always)]
    fn base(&self) -> *mut u8 {
        // The slice cannot wrap around the address space, so the conversion from usize
        // to isize will not wrap either.
        let len = self.0.len() as isize;
        unsafe { self.limit().offset(len) }
    }

    #[inline(always)]
    fn limit(&self) -> *mut u8 {
        self.0.as_ptr() as *mut u8
    }
}
