//! This module provides a very basic address-space management
//! API from user-space and implements a [`core::alloc::GlobalAlloc`]
//! type for doing memory allocation in user-space.

use core::alloc::{GlobalAlloc, Layout};
use core::mem::transmute;
use core::ptr::{self, NonNull};

use log::{error, warn};
use spin::Mutex;
use x86::current::paging::{PAddr, VAddr};

use kpi::SystemCallError;

use slabmalloc::*;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

#[cfg(target_os = "bespin")]
#[global_allocator]
static MEM_PROVIDER: crate::mem::SafeZoneAllocator = crate::mem::SafeZoneAllocator::new();

/// To use a ZoneAlloactor we require a lower-level allocator
/// (not provided by this crate) that can supply the allocator
/// with backing memory for `LargeObjectPage` and `ObjectPage` structs.
///
/// In our dummy implementation we just rely on the OS system allocator `alloc::System`.
pub struct Pager {
    sbrk: u64,
}

impl Pager {
    const BASE_PAGE_SIZE: usize = 4096;
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Allocates a given `page_size`.
    fn alloc_page(&mut self, page_size: usize) -> Option<*mut u8> {
        let (vaddr, _paddr) = self
            .allocate(Layout::from_size_align(page_size, page_size).unwrap())
            .expect("Can't allocate");
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

/// A pager for GlobalAlloc.

pub static mut PAGER: Mutex<Pager> = Mutex::new(Pager {
    sbrk: 0x52_0000_0000,
});

/// A SafeZoneAllocator that wraps the ZoneAllocator in a Mutex.
///
/// Note: This is not very scalable since we use a single big lock
/// around the allocator. There are better ways make the ZoneAllocator
/// thread-safe directly, but they are not implemented yet.
pub struct SafeZoneAllocator(Mutex<ZoneAllocator<'static>>);

impl SafeZoneAllocator {
    pub const fn new() -> SafeZoneAllocator {
        SafeZoneAllocator(Mutex::new(ZoneAllocator::new()))
    }
}

unsafe impl GlobalAlloc for SafeZoneAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match layout.size() {
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                let mut zone_allocator = self.0.lock();
                match zone_allocator.allocate(layout) {
                    Ok(nptr) => nptr.as_ptr(),
                    Err(AllocationError::OutOfMemory) => {
                        if layout.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            PAGER
                                .lock()
                                .allocate_page()
                                .map_or(ptr::null_mut(), |page| {
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
                            PAGER.lock().allocate_large_page().map_or(
                                ptr::null_mut(),
                                |large_page| {
                                    zone_allocator
                                        .refill_large(layout, large_page)
                                        .expect("Could not refill?");
                                    zone_allocator
                                        .allocate(layout)
                                        .expect("Should succeed after refill")
                                        .as_ptr()
                                },
                            )
                        }
                    }
                    Err(AllocationError::InvalidLayout) => panic!("Can't allocate this size"),
                }
            }
            ZoneAllocator::MAX_ALLOC_SIZE..=Pager::LARGE_PAGE_SIZE => {
                // Best to use the underlying backend directly to allocate large
                // to avoid fragmentation
                PAGER
                    .lock()
                    .allocate_large_page()
                    .expect("Can't allocate page?") as *mut _ as *mut u8
            }
            big_size => {
                // int a = (59 + (4 - 1)) / 4;
                let required_pages =
                    (big_size + Pager::LARGE_PAGE_SIZE - 1) / Pager::LARGE_PAGE_SIZE;
                let mut first: *mut u8 = ptr::null_mut();
                for _page_idx in 0..required_pages {
                    let ptr = PAGER
                        .lock()
                        .allocate_large_page()
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
            ZoneAllocator::MAX_ALLOC_SIZE..=Pager::LARGE_PAGE_SIZE => {
                PAGER.lock().dealloc_page(ptr, Pager::LARGE_PAGE_SIZE)
            }
            _ => error!("TODO: Currently can't dealloc of {:?}.", layout),
        }
    }
}
