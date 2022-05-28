// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A memory manager for use during emergencies.

use core::alloc::Layout;
use core::ptr::NonNull;

// We *might* want to implement AllocRef instead here
use slabmalloc::{self, LargeObjectPage, ObjectPage};

use crate::error::KError;
use crate::round_up;

use super::backends::PhysicalPageProvider;
use super::{Frame, PAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

/// A very simple allocator that only allocates and doesn't allow
/// deallocations (bump-style allocator).
///
/// It doesn't have to free because the memory allocated from it
/// typically lives forever. It's currently used only
/// when the system is in a panic state and we can't recover
/// from that.
///
/// TODO(panic-recovery): If we will eventually be able to partially
/// recover from panic using this in it's current form would be problematic
/// since we need to make sure that all the memory allocated from it
/// does not end up deallocated with e.g. the ZoneAllocator
/// (running ZoneAllocator's deallocate method on it mechanism
/// would surely lead to memory unsafety).
#[derive(Debug)]
pub(crate) struct EmergencyAllocator {
    pub index: usize,
    region: Frame,
}

impl Default for EmergencyAllocator {
    fn default() -> Self {
        Self::empty()
    }
}

impl EmergencyAllocator {
    pub(crate) const fn empty() -> Self {
        Self {
            index: 0,
            region: Frame::empty(),
        }
    }

    unsafe fn allocate_layout(&mut self, layout: Layout) -> Result<Frame, KError> {
        assert!(layout.align() <= BASE_PAGE_SIZE, "Alignment mismatch.");
        let size = round_up!(layout.size(), BASE_PAGE_SIZE);

        if size <= self.region.size() {
            // Create a new frame
            let (mut low, high) = self.region.split_at(size);
            low.zero();

            self.region = high;

            debug_assert_eq!(low.base % layout.align(), 0);
            debug_assert_eq!(low.base % BASE_PAGE_SIZE, 0);
            debug_assert!(low.size >= layout.size());

            Ok(low)
        } else {
            Err(KError::CacheExhausted)
        }
    }
}

// TODO(beautify) This is ugly we don't ant to use the slabmalloc allocator APIs.
// initially I thought we could reuse the code from the ZoneAllocator but
// the rust `impl Trait` functionality is too limited anyways
// so we might as well write custom code-paths that use the EmergencyAllocator
// inside GlobalAlloc...
unsafe impl<'a> slabmalloc::Allocator<'a> for EmergencyAllocator {
    fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, slabmalloc::AllocationError> {
        unsafe {
            let frame = self
                .allocate_layout(layout)
                .map_err(|_e| slabmalloc::AllocationError::OutOfMemory)?;
            Ok(NonNull::new_unchecked(
                frame.kernel_vaddr().as_mut_ptr::<u8>(),
            ))
        }
    }

    fn deallocate(
        &mut self,
        _ptr: NonNull<u8>,
        _layout: Layout,
    ) -> Result<(), slabmalloc::AllocationError> {
        Ok(())
    }

    unsafe fn refill(
        &mut self,
        _layout: Layout,
        new_page: &'a mut ObjectPage<'a>,
    ) -> Result<(), slabmalloc::AllocationError> {
        self.region = Frame::new(
            PAddr::from(new_page as *const _ as u64),
            BASE_PAGE_SIZE,
            0, /* should be local to us but really doesn't matter anyways anymore */
        );
        self.index = 0;

        Ok(())
    }

    unsafe fn refill_large(
        &mut self,
        _layout: Layout,
        new_page: &'a mut LargeObjectPage<'a>,
    ) -> Result<(), slabmalloc::AllocationError> {
        self.region = Frame::new(
            PAddr::from(new_page as *const _ as u64),
            LARGE_PAGE_SIZE,
            0, /* should be local to us but really doesn't matter anyways anymore */
        );
        self.index = 0;

        Ok(())
    }
}

/// A trait to allocate and release physical pages from an allocator.
impl PhysicalPageProvider for EmergencyAllocator {
    fn allocate_base_page(&mut self) -> Result<Frame, KError> {
        unsafe {
            let layout = Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE);
            self.allocate_layout(layout)
        }
    }

    fn release_base_page(&mut self, f: Frame) -> Result<(), KError> {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", f);
    }

    fn allocate_large_page(&mut self) -> Result<Frame, KError> {
        unimplemented!("Can't allocate large-pages with this")
    }

    fn release_large_page(&mut self, f: Frame) -> Result<(), KError> {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", f);
    }
}
