// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This module provides a very basic address-space management
//! API from user-space and implements a [`core::alloc::GlobalAlloc`]
//! type for doing memory allocation in user-space.

use core::alloc::{GlobalAlloc, Layout};
use core::mem::transmute;
use core::ptr::{self, NonNull};

use arrayvec::ArrayVec;
use lazy_static::lazy_static;
use log::{error, warn};
use spin::Mutex;

use kpi::arch::{PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

use kpi::process::{HEAP_PER_CORE_REGION, HEAP_START, MAX_CORES};
use kpi::SystemCallError;

use slabmalloc::*;

use lineup::tls2::Environment;

use crossbeam_utils::CachePadded;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

/// Start of large-page allocation (end of Zone allocator supported sizes)
const LPRANGE_START: usize = ZoneAllocator::MAX_ALLOC_SIZE + 1;

#[cfg(target_os = "nrk")]
#[global_allocator]
static PER_CORE_MEM_PROVIDER: crate::mem::PerCoreAllocator = crate::mem::PerCoreAllocator::new();

/// To use a ZoneAlloactor we require a lower-level allocator
/// (not provided by this crate) that can supply the allocator
/// with backing memory for `LargeObjectPage` and `ObjectPage` structs.
///
/// In our dummy implementation we just rely on the OS system allocator `alloc::System`.
pub struct Pager {
    sbrk: u64,
    limit: u64,
}

impl Pager {
    const BASE_PAGE_SIZE: usize = BASE_PAGE_SIZE;
    const LARGE_PAGE_SIZE: usize = LARGE_PAGE_SIZE;

    /// Allocates a given `page_size`.
    fn alloc_page(&mut self, page_size: usize) -> Option<*mut u8> {
        let (vaddr, _paddr) =
            match self.allocate(Layout::from_size_align(page_size, page_size).unwrap()) {
                Ok((vaddr, paddr)) => (vaddr, paddr),
                Err(_) => return None,
            };
        assert_ne!(vaddr.as_mut_ptr::<u8>(), ptr::null_mut());

        Some(vaddr.as_mut_ptr())
    }

    /// Allocates a given `page_size`.
    fn dealloc_page(&mut self, ptr: *mut u8, page_size: usize) {
        warn!("NYI dealloc page {:p} {:#x}", ptr, page_size);
    }

    pub(crate) fn allocate(&mut self, layout: Layout) -> Result<(VAddr, PAddr), SystemCallError> {
        let size = round_up!(layout.size(), 4096) as u64;
        self.sbrk = round_up!(self.sbrk as usize, core::cmp::max(layout.align(), 4096)) as u64;

        // Return out-of-memory error if the vaddr goes beyond the permissible limit.
        if self.sbrk >= self.limit {
            return Err(SystemCallError::OutOfMemory);
        }

        unsafe {
            let r = crate::syscalls::VSpace::map(self.sbrk, size)?;
            self.sbrk += size;
            Ok(r)
        }
    }

    /// Allocates a new ObjectPage from the System.
    fn allocate_page(&mut self) -> Option<&'static mut ObjectPage<'static>> {
        self.alloc_page(Pager::BASE_PAGE_SIZE)
            .map(|r| unsafe { transmute(r as usize) })
    }

    /// Release a ObjectPage back to the System.
    #[allow(unused)]
    fn release_page(&mut self, p: &'static mut ObjectPage<'static>) {
        warn!("lost ObjectPage");
    }

    /// Allocates a new LargeObjectPage from the system.
    fn allocate_large_page(&mut self) -> Option<&'static mut LargeObjectPage<'static>> {
        self.alloc_page(Pager::LARGE_PAGE_SIZE)
            .map(|r| unsafe { transmute(r as usize) })
    }

    /// Release a LargeObjectPage back to the System.
    #[allow(unused)]
    fn release_large_page(&mut self, p: &'static mut LargeObjectPage<'static>) {
        warn!("lost LargeObjectPage");
    }
}

lazy_static! {
    /// A pager for GlobalAlloc.
    pub static ref PAGER: ArrayVec::<CachePadded<Mutex<Pager>>, MAX_CORES> = {
        let mut pagers = ArrayVec::<CachePadded<Mutex<Pager>>, { MAX_CORES }>::new();
        for i in 0..MAX_CORES {
            let sbrk = (HEAP_START + (i * HEAP_PER_CORE_REGION)) as u64;
            let limit = (HEAP_START + ((i + 1) * HEAP_PER_CORE_REGION)) as u64;
            pagers.push(CachePadded::new(Mutex::new(Pager { sbrk, limit })));
        }
        pagers
    };
}

/// A SafeZoneAllocator that wraps the ZoneAllocator in a Mutex.
///
/// Note: This is not very scalable since we use a single big lock
/// around the allocator. There are better ways make the ZoneAllocator
/// thread-safe directly, but they are not implemented yet.
pub struct SafeZoneAllocator(CachePadded<Mutex<ZoneAllocator<'static>>>);

impl SafeZoneAllocator {
    pub const fn new() -> SafeZoneAllocator {
        SafeZoneAllocator(CachePadded::new(Mutex::new(ZoneAllocator::new())))
    }
}

unsafe impl GlobalAlloc for SafeZoneAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[inline(always)]
        unsafe fn try_alloc_page() -> Option<&'static mut ObjectPage<'static>> {
            let mut core_id = Environment::core_id();
            let my_core_id = core_id;

            loop {
                match PAGER[core_id].lock().allocate_page() {
                    Some(ret) => return Some(ret),
                    None => {
                        core_id = (core_id + 1) % MAX_CORES;
                        if core_id == (my_core_id - 1) % MAX_CORES {
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            None
        }

        #[inline(always)]
        unsafe fn try_alloc_largepage() -> Option<&'static mut LargeObjectPage<'static>> {
            let mut core_id = Environment::core_id();
            let my_core_id = core_id;

            loop {
                match PAGER[core_id].lock().allocate_large_page() {
                    Some(ret) => return Some(ret),
                    None => {
                        core_id = (core_id + 1) % MAX_CORES;
                        if core_id == (my_core_id - 1) % MAX_CORES {
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            None
        }

        match layout.size() {
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                let mut zone_allocator = self.0.lock();
                match zone_allocator.allocate(layout) {
                    Ok(nptr) => nptr.as_ptr(),
                    Err(AllocationError::OutOfMemory) => {
                        if layout.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            try_alloc_page().map_or(ptr::null_mut(), |page| {
                                zone_allocator
                                    .refill(layout, page)
                                    .expect("Could not refill?");
                                zone_allocator
                                    .allocate(layout)
                                    .expect("Should succeed after refill")
                                    .as_ptr()
                            })
                        } else {
                            // layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE
                            try_alloc_largepage().map_or(ptr::null_mut(), |large_page| {
                                zone_allocator
                                    .refill_large(layout, large_page)
                                    .expect("Could not refill?");
                                zone_allocator
                                    .allocate(layout)
                                    .expect("Should succeed after refill")
                                    .as_ptr()
                            })
                        }
                    }
                    Err(AllocationError::InvalidLayout) => panic!("Can't allocate this size"),
                }
            }
            LPRANGE_START..=Pager::LARGE_PAGE_SIZE => {
                // Best to use the underlying backend directly to allocate large
                // to avoid fragmentation
                try_alloc_largepage().expect("Can't allocate page?") as *mut _ as *mut u8
            }
            big_size => {
                // int a = (59 + (4 - 1)) / 4;
                let required_pages =
                    (big_size + Pager::LARGE_PAGE_SIZE - 1) / Pager::LARGE_PAGE_SIZE;
                let mut first: *mut u8 = ptr::null_mut();
                for _page_idx in 0..required_pages {
                    let ptr = try_alloc_largepage()
                        .expect("Can't allocate page for big allocation?")
                        as *mut _ as *mut u8;
                    if first.is_null() {
                        first = ptr;
                    }
                }

                first
            }
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE
            //&& layout.size() != x86::current::paging::BASE_PAGE_SIZE
            && new_size <= ZoneAllocator::get_max_size(layout.size()).unwrap_or(0x0)
        {
            // Don't do a re-allocation if we're in a big enough size-class
            // in the ZoneAllocator
            ptr
        } else {
            // Slow path, allocate a bigger region and de-allocate the old one
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new_ptr = self.alloc(new_layout);
            if !new_ptr.is_null() {
                ptr::copy_nonoverlapping(ptr, new_ptr, core::cmp::min(layout.size(), new_size));
                self.dealloc(ptr, layout);
            }
            new_ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match layout.size() {
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                if let Some(nptr) = NonNull::new(ptr) {
                    self.0
                        .lock()
                        .deallocate(nptr, layout)
                        .expect("Couldn't deallocate");
                } else {
                    // Nothing to do (don't dealloc null pointers).
                }

                // An proper reclamation strategy could be implemented here
                // to release empty pages back from the ZoneAllocator to the PAGER
            }
            LPRANGE_START..=Pager::LARGE_PAGE_SIZE => PAGER[Environment::core_id()]
                .lock()
                .dealloc_page(ptr, Pager::LARGE_PAGE_SIZE),
            _ => error!("TODO: Currently can't dealloc of {:?}.", layout),
        }
    }
}

pub struct PerCoreAllocator;

lazy_static! {
    pub static ref PER_CORE_MEM_ALLOCATOR: [SafeZoneAllocator; MAX_CORES] = {
        let mut allocators = ArrayVec::<SafeZoneAllocator, MAX_CORES>::new();
        for _i in 0..MAX_CORES {
            allocators.push(SafeZoneAllocator(CachePadded::new(Mutex::new(
                ZoneAllocator::new(),
            ))));
        }
        match allocators.into_inner() {
            Ok(allocators) => allocators,
            Err(_) => unreachable!("Unable to convert ArrayVec to array"),
        }
    };
}

impl PerCoreAllocator {
    pub const fn new() -> PerCoreAllocator {
        PerCoreAllocator {}
    }
}

unsafe impl GlobalAlloc for PerCoreAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Get the core_id we are currently running on. Then return alloc of that SafeZoneAllocator.
        let sza = &PER_CORE_MEM_ALLOCATOR[Environment::core_id()];
        sza.alloc(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let sza = &PER_CORE_MEM_ALLOCATOR[Environment::core_id()];
        sza.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let sza = &PER_CORE_MEM_ALLOCATOR[Environment::core_id()];
        sza.dealloc(ptr, layout)
    }
}
