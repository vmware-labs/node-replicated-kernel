// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The core module for kernel memory management.
//!
//! Defines some core data-types and implements
//! a bunch of different allocators for use in the system.
//!
//! From a high level the four most interesting types in here are:
//!  * The Frame: Which is represents a block of physical memory, it's always
//!    aligned to, and a multiple of a base-page. Ideally Rust affine types
//!    should ensure we always only have one Frame covering a block of memory.
//!  * The NCache: A big stack of base and large-pages.
//!  * The TCache: A smaller stack of base and large-pages.
//!  * The KernelAllocator: Which implements GlobalAlloc.
use core::alloc::{GlobalAlloc, Layout};
use core::intrinsics::likely;
use core::mem::transmute;
use core::sync::atomic::AtomicU64;
use core::{fmt, ptr};

use arrayvec::ArrayVec;
use log::{debug, error, trace, warn};
use slabmalloc::{Allocator, ZoneAllocator};
use spin::Mutex;
use x86::bits64::paging;

use crate::arch::MAX_NUMA_NODES;
use crate::prelude::*;
use crate::{kcb, round_up};

/// Re-export arch specific memory definitions
pub use crate::arch::memory::{
    kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, BASE_PAGE_SIZE, KERNEL_BASE,
    LARGE_PAGE_SIZE,
};
pub use kpi::MemType;

use vspace::MapAction;

pub mod detmem;
pub mod emem;
pub mod mcache;
pub mod vspace;
#[cfg(test)]
pub mod vspace_model;

/// How many initial physical memory regions we support.
pub const MAX_PHYSICAL_REGIONS: usize = 64;

/// The global allocator in the kernel.
//#[cfg(not(any(test, fuzzing)))]
#[cfg(target_os = "none")]
#[global_allocator]
static MEM_PROVIDER: KernelAllocator = KernelAllocator {
    big_objects_sbrk: AtomicU64::new(
        KERNEL_BASE + (2048 * x86::bits64::paging::HUGE_PAGE_SIZE) as u64,
    ),
};

/// Different types of allocator that the KernelAllocator can use.
#[derive(Debug, PartialEq)]
enum AllocatorType {
    /// An instance of slabmalloc::ZoneAllocator
    Zone,
    /// A memory manager that implements trait XX.
    MemManager,
    /// Large regions that get map in the kernel VSpace by the `KernelAllocator`.
    MapBig,
}

/// Implements the kernel memory allocation strategy.
pub struct KernelAllocator {
    big_objects_sbrk: AtomicU64,
}

/// Calculate how many base and large pages we need to fit a given size.
///
/// # Returns
/// A tuple containing (base-pages, large-pages).
/// base-pages will never exceed LARGE_PAGE_SIZE / BASE_PAGE_SIZE.
pub fn size_to_pages(size: usize) -> (usize, usize) {
    let bytes_not_in_large = size % LARGE_PAGE_SIZE;

    let div = bytes_not_in_large / BASE_PAGE_SIZE;
    let rem = bytes_not_in_large % BASE_PAGE_SIZE;
    let base_pages = if rem > 0 { div + 1 } else { div };

    let remaining_size = size - bytes_not_in_large;
    let div = remaining_size / LARGE_PAGE_SIZE;
    let rem = remaining_size % LARGE_PAGE_SIZE;
    let large_pages = if rem > 0 { div + 1 } else { div };

    (base_pages, large_pages)
}

impl KernelAllocator {
    /// Try to allocate a piece of memory.
    fn try_alloc(&self, layout: Layout) -> Result<ptr::NonNull<u8>, KError> {
        let kcb = kcb::try_get_kcb().ok_or(KError::KcbUnavailable)?;
        match KernelAllocator::allocator_for(layout) {
            AllocatorType::Zone if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE => {
                // TODO(rust): Silly code duplication follows if/else
                if core::intrinsics::unlikely(kcb.in_panic_mode) {
                    let mut zone_allocator = kcb.ezone_allocator()?;
                    zone_allocator.allocate(layout).map_err(|e| e.into())
                } else {
                    let mut zone_allocator = kcb.zone_allocator()?;
                    zone_allocator.allocate(layout).map_err(|e| e.into())
                }
            }
            AllocatorType::MemManager if layout.size() <= LARGE_PAGE_SIZE => {
                let mut pmanager = kcb.try_mem_manager()?;
                let f = pmanager.allocate_large_page()?;
                unsafe { Ok(ptr::NonNull::new_unchecked(f.kernel_vaddr().as_mut_ptr())) }
            }
            AllocatorType::MapBig => {
                // Big objects are mapped into the kernel address space

                // This needs some <3:
                // * TODO(safety): Assumptions are PML4 slot 129 (big_objects_sbrk) is always free for MapBig
                // * TODO(ugly): 129 is also hard-coded in process creation
                // * TODO(safety): No bounds checking
                // * TODO(smp): Needs a spin-lock for multi-core
                // * TODO(checks): we want this case to be rare so if we end up with more than ~20
                //   big objects we should print ag warning (and start rethinking this)
                // * TODO(limitation): We can't really allocate more than what fits in a TCache

                // Figure out how much we need to map:
                let (mut base, mut large) = KernelAllocator::layout_to_pages(layout);

                // TODO(hack): Fetching more than 254 base pages would exhaust our TCache so might
                // as well get a large-page instead:
                // Slightly better: Should at least have well defined constants for `254`
                // A bit better: TCache should probably have more space base pages (like 2MiB of base pages?)
                // More better: If we need more pages than what fits in the TCache, we should get it directly
                // from the NCache?
                // Even Better: Find a good way to express this API, and maybe the whole GlobalAllocator
                // infrastructure that doesn't require estimating the pages upfront?
                if base > 254 {
                    base = 0;
                    large += 1;
                }
                // TODO(correctness): Make sure we have 20 pages for page-tables
                // so vspace ops don't fail us :/
                self.maybe_refill_tcache(base + 20, large)?;

                // We allocate (large+1) * large-page-size
                // the +1 is to account for space for all the base-pages
                // and to make sure next time we're still aligned to a 2 MiB
                // boundary
                let mut start_at = self.big_objects_sbrk.fetch_add(
                    ((large + 1) * LARGE_PAGE_SIZE) as u64,
                    core::sync::atomic::Ordering::SeqCst,
                );
                trace!(
                    "Got a large allocation {:?}, need bp {} lp {} {:#x}",
                    layout,
                    base,
                    large,
                    start_at
                );

                let base_ptr = unsafe { ptr::NonNull::new_unchecked(start_at as *mut u8) };

                let mut kvspace = kcb.arch.init_vspace();
                for _ in 0..large {
                    let mut pmanager = kcb.try_mem_manager()?;
                    let f = pmanager
                        .allocate_large_page()
                        .expect("Can't run out of memory");
                    drop(pmanager); // `map_generic` might try to re-acquire mem_manager

                    kvspace
                        .map_generic(
                            VAddr::from(start_at),
                            (f.base, f.size()),
                            MapAction::ReadWriteKernel,
                            true,
                        )
                        .expect("Can't create the mapping");

                    start_at += LARGE_PAGE_SIZE as u64;
                }

                for _ in 0..base {
                    let mut pmanager = kcb.try_mem_manager()?;
                    let f = pmanager
                        .allocate_base_page()
                        .expect("Can't run out of memory");
                    drop(pmanager); // `map_generic` might try to re-acquire mem_manager

                    kvspace
                        .map_generic(
                            VAddr::from(start_at),
                            (f.base, f.size()),
                            MapAction::ReadWriteKernel,
                            true,
                        )
                        .expect("Can't create the mapping");
                    start_at += BASE_PAGE_SIZE as u64;
                }

                Ok(base_ptr)
            }
            _ => unimplemented!("Unable to handle this allocation request {:?}", layout),
        }
    }

    /// Determines which Allocator to use for a given Layout.
    fn allocator_for(layout: Layout) -> AllocatorType {
        const MAX_ALLOC_PLUS_ONE: usize = ZoneAllocator::MAX_ALLOC_SIZE + 1;
        match layout.size() {
            0..=ZoneAllocator::MAX_ALLOC_SIZE => AllocatorType::Zone,
            MAX_ALLOC_PLUS_ONE..=LARGE_PAGE_SIZE => AllocatorType::MemManager,
            _ => AllocatorType::MapBig,
        }
    }

    /// Try to refill our core-local zone allocator.
    ///
    /// We come here if a previous allocation failed.
    fn try_refill(&self, layout: Layout, e: KError) -> Result<(), KError> {
        match (KernelAllocator::allocator_for(layout), e) {
            (AllocatorType::Zone, KError::CacheExhausted) => {
                let (needed_base_pages, needed_large_pages) =
                    KernelAllocator::refill_amount(layout);
                self.maybe_refill_tcache(needed_base_pages, needed_large_pages)?;
                self.try_refill_zone(layout)
            }
            (AllocatorType::MapBig, _) => {
                let (needed_base_pages, needed_large_pages) =
                    KernelAllocator::refill_amount(layout);
                KernelAllocator::try_refill_tcache(
                    needed_base_pages,
                    needed_large_pages,
                    MemType::DRAM,
                )
            }
            (AllocatorType::MemManager, _) => {
                let (needed_base_pages, needed_large_pages) =
                    KernelAllocator::refill_amount(layout);
                KernelAllocator::try_refill_tcache(
                    needed_base_pages,
                    needed_large_pages,
                    MemType::DRAM,
                )
            }
            (AllocatorType::Zone, _) => unreachable!("Not sure how to handle"),
        }
    }

    /// Calculate how many base and large pages we need to fit a Layout.
    fn layout_to_pages(layout: Layout) -> (usize, usize) {
        size_to_pages(layout.size())
    }

    /// Determine for a Layout how many pages we need taking into
    /// account the type of allocator that will end up handling the request.
    fn refill_amount(layout: Layout) -> (usize, usize) {
        match KernelAllocator::allocator_for(layout) {
            AllocatorType::Zone => {
                if layout.size() <= slabmalloc::ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                    (1, 0)
                } else {
                    (0, 1)
                }
            }
            AllocatorType::MemManager => {
                if layout.size() <= BASE_PAGE_SIZE {
                    (1, 0)
                } else {
                    (0, 1)
                }
            }
            AllocatorType::MapBig => KernelAllocator::layout_to_pages(layout),
        }
    }

    /// Try to refill our core-local tcache.
    pub fn try_refill_tcache(
        needed_base_pages: usize,
        needed_large_pages: usize,
        mem_type: MemType,
    ) -> Result<(), KError> {
        let kcb = kcb::try_get_kcb().ok_or(KError::KcbUnavailable)?;
        if mem_type == MemType::DRAM && kcb.physical_memory.gmanager.is_none() {
            // No gmanager, can't refill then, let's hope it works anyways...
            return Ok(());
        }
        if mem_type == MemType::PMEM && kcb.pmem_memory.gmanager.is_none() {
            // No gmanager, can't refill then, let's hope it works anyways...
            return Ok(());
        }

        let (gmanager, mut mem_manager, affinity) = match mem_type {
            MemType::DRAM => (
                kcb.physical_memory.gmanager.unwrap(),
                kcb.try_mem_manager()?,
                kcb.physical_memory.affinity as usize,
            ),
            MemType::PMEM => (
                kcb.pmem_memory.gmanager.unwrap(),
                kcb.pmem_manager(),
                kcb.pmem_memory.affinity as usize,
            ),
            _ => unreachable!(),
        };
        let mut ncache = gmanager.node_caches[affinity].lock();
        // Make sure we don't overflow the TCache
        let needed_base_pages =
            core::cmp::min(mem_manager.spare_base_page_capacity(), needed_base_pages);
        let needed_large_pages =
            core::cmp::min(mem_manager.spare_large_page_capacity(), needed_large_pages);

        for _i in 0..needed_base_pages {
            let frame = ncache.allocate_base_page()?;
            mem_manager
                .grow_base_pages(&[frame])
                .expect("We ensure to not overfill the TCache above.");
        }

        for _i in 0..needed_large_pages {
            let frame = ncache.allocate_large_page()?;
            mem_manager
                .grow_large_pages(&[frame])
                .expect("We ensure to not overfill the TCache above.");
        }

        Ok(())
    }

    /// Refill TCache only if the layout will exhaust the cache's current
    /// stored memory
    ///
    /// `let (needed_base_pages, needed_large_pages) = KernelAllocator::refill_amount(layout);`
    fn maybe_refill_tcache(
        &self,
        needed_base_pages: usize,
        needed_large_pages: usize,
    ) -> Result<(), KError> {
        let kcb = kcb::try_get_kcb().ok_or(KError::KcbUnavailable)?;
        let mem_manager = kcb.try_mem_manager()?;

        let free_bp = mem_manager.free_base_pages();
        let free_lp = mem_manager.free_large_pages();

        // Dropping things, as they'll get reacquired in try_refill_tcache
        drop(mem_manager);

        if needed_base_pages > free_bp || needed_large_pages > free_lp {
            debug!(
                "Refilling the TCache: needed_bp {} needed_lp {} free_bp {} free_lp {}",
                needed_base_pages, needed_large_pages, free_bp, free_lp
            );
            KernelAllocator::try_refill_tcache(needed_base_pages, needed_large_pages, MemType::DRAM)
        } else {
            debug!(
                "Refilling unnecessary: needed_bp {} needed_lp {} free_bp {} free_lp {}",
                needed_base_pages, needed_large_pages, free_bp, free_lp
            );

            Ok(())
        }
    }

    /// Try refill zone
    fn try_refill_zone(&self, layout: Layout) -> Result<(), KError> {
        let kcb = kcb::try_get_kcb().ok_or(KError::KcbUnavailable)?;
        let needs_a_base_page = layout.size() <= slabmalloc::ZoneAllocator::MAX_BASE_ALLOC_SIZE;

        let mut mem_manager = kcb.try_mem_manager()?;
        // TODO(rust): Silly code duplication follows if/else
        if core::intrinsics::unlikely(kcb.in_panic_mode) {
            let mut zone = kcb.ezone_allocator()?;
            if needs_a_base_page {
                let frame = mem_manager.allocate_base_page()?;
                unsafe {
                    let base_page_ptr: *mut slabmalloc::ObjectPage =
                        frame.uninitialized::<slabmalloc::ObjectPage>().as_mut_ptr();
                    zone.refill(layout, &mut *base_page_ptr)
                        .expect("This should always succeed");
                }
            } else {
                // Needs a large page
                let frame = mem_manager.allocate_large_page()?;
                unsafe {
                    let large_page_ptr: *mut slabmalloc::LargeObjectPage = frame
                        .uninitialized::<slabmalloc::LargeObjectPage>()
                        .as_mut_ptr();
                    zone.refill_large(layout, &mut *large_page_ptr)
                        .expect("This should always succeed");
                }
            }
        } else {
            let mut zone = kcb.zone_allocator()?;
            if needs_a_base_page {
                let frame = mem_manager.allocate_base_page()?;
                unsafe {
                    let base_page_ptr: *mut slabmalloc::ObjectPage =
                        frame.uninitialized::<slabmalloc::ObjectPage>().as_mut_ptr();
                    zone.refill(layout, &mut *base_page_ptr)
                        .expect("This should always succeed");
                }
            } else {
                // Needs a large page
                let frame = mem_manager.allocate_large_page()?;
                unsafe {
                    let large_page_ptr: *mut slabmalloc::LargeObjectPage = frame
                        .uninitialized::<slabmalloc::LargeObjectPage>()
                        .as_mut_ptr();
                    zone.refill_large(layout, &mut *large_page_ptr)
                        .expect("This should always succeed");
                }
            }
        }
        Ok(())
    }
}

/// Implementation of GlobalAlloc for the kernel.
///
/// The algorithm in alloc/dealloc should take care of allocating kernel objects of
/// various sizes and is responsible for balancing the memory between different
/// allocators.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        for _tries in 0..3 {
            let res = self.try_alloc(layout);
            match res {
                // Allocation worked
                Ok(nptr) => {
                    return nptr.as_ptr();
                }
                Err(KError::KcbUnavailable) => {
                    unreachable!(
                        "Bug; trying to get KCB 2x in during `try_alloc` {:?}",
                        layout
                    );
                }
                Err(KError::ManagerAlreadyBorrowed) => {
                    unreachable!(
                        "ManagerAlreadyBorrowed trying to get mem manager 2x during `try_alloc`"
                    );
                }
                Err(e) => {
                    // Allocation didn't work, we try to refill
                    match self.try_refill(layout, e) {
                        Ok(_) => {
                            // Refilling worked, re-try allocation
                            continue;
                        }
                        Err(KError::KcbUnavailable) => {
                            error!("KcbUnavailable trying to get KCB during `try_refill`");
                            break;
                        }
                        Err(KError::ManagerAlreadyBorrowed) => {
                            error!("ManagerAlreadyBorrowed trying to get mem manager 2x during `try_refill` {:?}", layout);
                            break;
                        }
                        Err(_e) => {
                            // Refilling failed, re-try allocation
                            return ptr::null_mut();
                        }
                    }
                }
            }
        }

        ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::kcb::try_get_kcb().map_or_else(
            || {
                unreachable!("Trying to deallocate {:p} {:?} without a KCB.", ptr, layout);
            },
            |kcb| {
                if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
                    // TODO(rust): Silly code duplication follows if/else
                    if core::intrinsics::unlikely(kcb.in_panic_mode) {
                        let mut zone_allocator = kcb
                            .ezone_allocator()
                            .expect("Can't borrow ezone_allocator?");
                        if likely(!ptr.is_null()) {
                            zone_allocator
                                .deallocate(ptr::NonNull::new_unchecked(ptr), layout)
                                .expect("Can't deallocate?");
                        } else {
                            warn!("Ignore null pointer deallocation");
                        }
                    } else {
                        let mut zone_allocator =
                            kcb.zone_allocator().expect("Can't borrow zone_allocator?");
                        if likely(!ptr.is_null()) {
                            zone_allocator
                                .deallocate(ptr::NonNull::new_unchecked(ptr), layout)
                                .expect("Can't deallocate?");
                        } else {
                            warn!("Ignore null pointer deallocation");
                        }
                    }
                } else {
                    let kcb = kcb::get_kcb();
                    let mut fmanager = kcb.mem_manager();

                    if layout.size() <= BASE_PAGE_SIZE {
                        assert!(layout.align() <= BASE_PAGE_SIZE);
                        let frame = Frame::new(
                            kernel_vaddr_to_paddr(VAddr::from_u64(ptr as u64)),
                            BASE_PAGE_SIZE,
                            // TODO(numa-correctness): This is not necessarily correct as free can happen
                            // while `physical_memory` changes to different affinities
                            // we try to avoid this at the moment by being careful about freeing things
                            // during changes to allocation affinity (the NCache or TCache would panic)
                            kcb.physical_memory.affinity,
                        );

                        match fmanager.release_base_page(frame) {
                            Ok(_) => { /* Frame addition to tcache as successful.*/ }
                            Err(_e) => match kcb.physical_memory.gmanager {
                                // Try adding frame to ncache.
                                Some(gmanager) => {
                                    let mut ncache =
                                        gmanager.node_caches[frame.affinity as usize].lock();
                                    ncache
                                        .release_base_page(frame)
                                        .expect("Can't deallocate frame");
                                }
                                None => unreachable!("Unable to access global memory manager"),
                            },
                        }
                    } else if layout.size() <= LARGE_PAGE_SIZE {
                        assert!(layout.align() <= LARGE_PAGE_SIZE);
                        let frame = Frame::new(
                            kernel_vaddr_to_paddr(VAddr::from_u64(ptr as u64)),
                            LARGE_PAGE_SIZE,
                            // TODO(numa-correctness): This is not necessarily correct as free can happen
                            // while `physical_memory` changes to different affinities
                            // we try to avoid this at the moment by being careful about freeing things
                            // during changes to allocation affinity (the NCache or TCache would panic)
                            kcb.physical_memory.affinity,
                        );

                        fmanager
                            .release_large_page(frame)
                            .expect("Can't deallocate frame");
                    } else {
                        error!("Loosing large memory region. Oh well.")
                    }
                }
            },
        );
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        crate::kcb::try_get_kcb().map_or_else(
            || {
                unreachable!("Trying to reallocate {:p} {:?} without a KCB.", ptr, layout);
            },
            |kcb| {
                if !kcb.in_panic_mode
                    && layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE
                    && layout.size() != BASE_PAGE_SIZE
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
                        ptr::copy_nonoverlapping(
                            ptr,
                            new_ptr,
                            core::cmp::min(layout.size(), new_size),
                        );
                        self.dealloc(ptr, layout);
                    }
                    new_ptr
                }
            },
        )
    }
}

/// Human-readable representation of a data-size.
///
/// # Notes
/// Use for pretty printing and debugging only.
#[derive(PartialEq)]
pub enum DataSize {
    Bytes(f64),
    KiB(f64),
    MiB(f64),
    GiB(f64),
}

impl DataSize {
    /// Construct a new DataSize passing the amount of `bytes`
    /// we want to convert
    pub fn from_bytes(bytes: usize) -> DataSize {
        if bytes < 1024 {
            DataSize::Bytes(bytes as f64)
        } else if bytes < (1024 * 1024) {
            DataSize::KiB(bytes as f64 / 1024.0)
        } else if bytes < (1024 * 1024 * 1024) {
            DataSize::MiB(bytes as f64 / (1024 * 1024) as f64)
        } else {
            DataSize::GiB(bytes as f64 / (1024 * 1024 * 1024) as f64)
        }
    }

    /// Write rounded size and SI unit to `f`
    fn format(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DataSize::Bytes(n) => write!(f, "{:.2} B", n),
            DataSize::KiB(n) => write!(f, "{:.2} KiB", n),
            DataSize::MiB(n) => write!(f, "{:.2} MiB", n),
            DataSize::GiB(n) => write!(f, "{:.2} GiB", n),
        }
    }
}

impl fmt::Debug for DataSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format(f)
    }
}

impl fmt::Display for DataSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format(f)
    }
}

/// Represents the global memory system in the kernel.
///
/// `node_caches` and and `emem` can be accessed concurrently and are protected
/// by a simple spin-lock (for reclamation and allocation).
/// TODO(perf): This may need a more elaborate scheme in the future.
#[derive(Default)]
pub struct GlobalMemory {
    /// Holds a small amount of memory for every NUMA node.
    ///
    /// Used to initialize the system.
    pub(crate) emem: ArrayVec<Mutex<mcache::TCache>, MAX_NUMA_NODES>,

    /// All node-caches in the system (one for every NUMA node).
    pub(crate) node_caches:
        ArrayVec<CachePadded<Mutex<&'static mut mcache::NCache>>, MAX_NUMA_NODES>,
}

impl GlobalMemory {
    /// Construct a new global memory object from a range of initial memory frames.
    /// This is typically invoked quite early (we're setting up support for memory allocation).
    ///
    /// We first chop off a small amount of memory from the frames to construct an early
    /// TCache (for every NUMA node). Then we construct the big node-caches (NCache) and
    /// populate them with remaining (hopefully a lot) memory.
    ///
    /// When this completes we have a bunch of global NUMA aware memory allocators that
    /// are protected by spin-locks. `GlobalMemory` together with the core-local allocators
    /// forms the tracking for our memory allocation system.
    ///
    /// # Safety
    /// Pretty unsafe as we do lot of conjuring objects from frames to allocate memory
    /// for our allocators.
    /// A client needs to ensure that our frames are valid memory, and not yet
    /// being used anywhere yet.
    /// The good news is that we only invoke this once during bootstrap.
    pub unsafe fn new(
        mut memory: ArrayVec<Frame, MAX_PHYSICAL_REGIONS>,
    ) -> Result<GlobalMemory, KError> {
        assert!(memory.is_sorted_by(|a, b| a.affinity.partial_cmp(&b.affinity)));

        debug_assert!(!memory.is_empty());
        let mut gm = GlobalMemory::default();

        // How many NUMA nodes are there in the system
        let max_affinity: usize = memory
            .iter()
            .map(|f| f.affinity as usize)
            .max()
            .expect("Need at least some frames")
            + 1;

        // Construct the `emem`'s for all NUMA nodes:
        let mut cur_affinity = 0;
        // Top of the frames that we didn't end up using for the `emem` construction
        let mut leftovers: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
        for frame in memory.iter_mut() {
            const EMEM_SIZE: usize = 2 * LARGE_PAGE_SIZE + 64 * BASE_PAGE_SIZE;
            if frame.affinity == cur_affinity && frame.size() > EMEM_SIZE {
                // Let's make sure we have a frame that starts at a 2 MiB boundary which makes it easier
                // to populate the TCache
                let (low, large_page_aligned_frame) = frame.split_at_nearest_large_page_boundary();
                *frame = low;

                // Cut-away the top memory if the frame we got is too big
                let (emem, leftover_mem) = large_page_aligned_frame.split_at(EMEM_SIZE);
                if leftover_mem != Frame::empty() {
                    // And safe it for later processing
                    leftovers.push(leftover_mem);
                }

                gm.emem.push(Mutex::new(mcache::TCache::new_with_frame(
                    cur_affinity,
                    emem,
                )));

                cur_affinity += 1;
            }
        }
        // If this fails, memory is really fragmented or some nodes have no/little memory
        assert_eq!(
            gm.emem.len(),
            max_affinity,
            "Added early managers for all NUMA nodes"
        );

        // Construct an NCache for all nodes
        for affinity in 0..max_affinity {
            let mut ncache_memory = gm.emem[affinity].lock().allocate_large_page()?;
            let ncache_memory_addr: PAddr = ncache_memory.base;
            assert!(ncache_memory_addr != PAddr::zero());
            ncache_memory.zero(); // TODO(perf) this happens twice atm?

            let ncache_ptr = ncache_memory.uninitialized::<mcache::NCache>();

            let ncache: &'static mut mcache::NCache = mcache::NCache::init(ncache_ptr, affinity);
            debug_assert_eq!(
                &*ncache as *const _ as u64,
                paddr_to_kernel_vaddr(ncache_memory_addr).as_u64()
            );

            gm.node_caches.push(CachePadded::new(Mutex::new(ncache)));
        }

        // Populate the NCaches with all remaining memory
        // Ideally we fully exhaust all frames and put everything in the NCache
        for (ncache_affinity, ncache) in gm.node_caches.iter().enumerate() {
            let mut ncache_locked = ncache.lock();
            for frame in memory.iter() {
                if frame.affinity == ncache_affinity {
                    trace!("Trying to add {:?} frame to {:?}", frame, ncache_locked);
                    ncache_locked.populate_2m_first(*frame);
                }
            }
            for frame in leftovers.iter() {
                if frame.affinity == ncache_affinity {
                    trace!("Trying to add {:?} frame to {:?}", frame, ncache_locked);
                    ncache_locked.populate_2m_first(*frame);
                }
            }
        }

        Ok(gm)
    }
}

impl fmt::Debug for GlobalMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("GlobalMemory");

        for idx in 0..self.node_caches.len() {
            // TODO(correctness): rather than maybe run into a deadlock here
            // (e.g., if we are trying to print GlobalMemory when in a panic),
            // the relevant fields for printing Debug should probably
            // just be atomics
            let ncache = self.node_caches[idx].lock();
            f.field("NCache", &ncache);
        }

        f.finish()
    }
}

/// A trait to allocate and release physical pages from an allocator.
pub trait PhysicalPageProvider {
    /// Allocate a `BASE_PAGE_SIZE` for the given architecture from the allocator.
    fn allocate_base_page(&mut self) -> Result<Frame, KError>;
    /// Release a `BASE_PAGE_SIZE` for the given architecture back to the allocator.
    fn release_base_page(&mut self, f: Frame) -> Result<(), KError>;

    /// Allocate a `LARGE_PAGE_SIZE` for the given architecture from the allocator.
    fn allocate_large_page(&mut self) -> Result<Frame, KError>;
    /// Release a `LARGE_PAGE_SIZE` for the given architecture back to the allocator.
    fn release_large_page(&mut self, f: Frame) -> Result<(), KError>;
}

/// The backend implementation necessary to implement if we want a client to be
/// able to grow our allocator by providing a list of frames.
pub trait GrowBackend {
    /// How much capacity we have left to add base pages.
    fn spare_base_page_capacity(&self) -> usize;

    /// Add a slice of base-pages to `self`.
    fn grow_base_pages(&mut self, free_list: &[Frame]) -> Result<(), KError>;

    /// How much capacity we have left to add large pages.
    fn spare_large_page_capacity(&self) -> usize;

    /// Add a slice of large-pages to `self`.
    fn grow_large_pages(&mut self, free_list: &[Frame]) -> Result<(), KError>;
}

/// The backend implementation necessary to implement if we want
/// a system manager to take away be able to take away memory
/// from our allocator.
pub trait ReapBackend {
    /// Ask to give base-pages back.
    ///
    /// An implementation should put the pages in the `free_list` and remove
    /// them from the local allocator.
    fn reap_base_pages(&mut self, free_list: &mut [Option<Frame>]);

    /// Ask to give large-pages back.
    ///
    /// An implementation should put the pages in the `free_list` and remove
    /// them from the local allocator.
    fn reap_large_pages(&mut self, free_list: &mut [Option<Frame>]);
}

/// Provides information about the allocator.
pub trait AllocatorStatistics {
    /// Current free memory (in bytes) this allocator has.
    fn free(&self) -> usize {
        self.size() - self.allocated()
    }

    /// Memory (in bytes) that was handed out by this allocator
    /// and has not yet been reclaimed (memory currently in use).
    fn allocated(&self) -> usize;

    /// Total memory (in bytes) that is maintained by this allocator.
    fn size(&self) -> usize;

    /// Potential capacity (in bytes) that the allocator can maintain.
    ///
    /// Some allocator may have unlimited capacity, in that case
    /// they can return usize::max.
    ///
    /// e.g. this should hold `capacity() >= free() + allocated()`
    fn capacity(&self) -> usize;

    /// Internal fragmentation produced by this allocator (in bytes).
    ///
    /// In some cases an allocator may not be able to calculate it.
    fn internal_fragmentation(&self) -> usize;

    fn free_base_pages(&self) -> usize {
        0
    }

    fn free_large_pages(&self) -> usize {
        0
    }
}

pub trait PhysicalAllocator {
    /// Allocates a frame meeting the size and alignment
    /// guarantees of layout.
    ///
    /// If this method returns an Ok(frame), then the frame returned
    /// will be a frame pointing to a block of storage suitable for
    /// holding an instance of layout.
    ///
    /// The returned block of storage may or may not have its
    /// contents initialized.
    ///
    /// This method allocates at least a multiple of `BASE_PAGE_SIZE`
    /// so it can result in large amounts of internal fragmentation.
    unsafe fn allocate_frame(&mut self, layout: Layout) -> Result<Frame, KError>;

    /// Give a frame previously allocated using `allocate_frame` back
    /// to the physical memory allocator.
    ///
    /// # Safety
    ///
    /// - frame must denote a block of memory currently allocated via this allocator,
    /// - layout must fit that block of memory,
    /// - In addition to fitting the block of memory layout,
    ///   the alignment of the layout must match the alignment
    ///   used to allocate that block of memory.
    unsafe fn deallocate_frame(&mut self, frame: Frame, layout: Layout);
}

/// Physical region of memory.
///
/// A frame is always aligned to a page-size.
/// A frame's size is a multiple of `BASE_PAGE_SIZE`.
///
/// # Note on naming
/// Historically frames refer to physical (base)-pages in OS terminology.
/// In our case a frame can be a multiple of a page -- it may be more fitting
/// to call it a memory-block.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Frame {
    pub base: PAddr,
    pub size: usize,
    pub affinity: atopology::NodeId,
}

impl Frame {
    /// Make a new Frame at `base` with `size`
    pub const fn const_new(base: PAddr, size: usize, node: atopology::NodeId) -> Frame {
        //assert_ne!(base, PAddr::zero());
        //assert_eq!(base % BASE_PAGE_SIZE, 0);
        //assert!(node < MAX_TOPOLOGIES);

        Frame {
            base,
            size,
            affinity: node,
        }
    }

    /// Create a new Frame given a PAddr range (from, to)
    pub fn from_range(range: (PAddr, PAddr), node: atopology::NodeId) -> Frame {
        assert_eq!(range.0 % BASE_PAGE_SIZE, 0);
        assert_eq!(range.1 % BASE_PAGE_SIZE, 0);
        assert!(range.0 < range.1);

        Frame {
            base: range.0,
            size: (range.1 - range.0).into(),
            affinity: node,
        }
    }

    /// Make a new Frame at `base` with `size` with affinity `node`.
    pub fn new(base: PAddr, size: usize, node: atopology::NodeId) -> Frame {
        assert_eq!(base % BASE_PAGE_SIZE, 0);
        assert_eq!(size % BASE_PAGE_SIZE, 0);

        Frame {
            base,
            size,
            affinity: node,
        }
    }

    /// Construct an empty, zero-length Frame.
    pub const fn empty() -> Frame {
        Frame {
            base: PAddr::zero(),
            size: 0,
            affinity: 0,
        }
    }

    /// Represent the Frame as a mutable slice of `T`.
    ///
    /// TODO: Bug (should we panic if we don't fit
    /// T's exactly?)
    unsafe fn as_mut_slice<T>(&mut self) -> Option<&mut [T]> {
        if self.size % core::mem::size_of::<T>() == 0 {
            Some(core::slice::from_raw_parts_mut(
                self.kernel_vaddr().as_mut_ptr::<T>(),
                self.size / core::mem::size_of::<T>(),
            ))
        } else {
            None
        }
    }

    /// Splits a given Frame into two (`low`, `high`).
    ///
    /// - `high` will be aligned to LARGE_PAGE_SIZE or Frame::empty() if
    ///    the frame can not be aligned to a large-page within its size.
    /// - `low` will be everything below alignment or Frame::empty() if `self`
    ///    is already aligned to `LARGE_PAGE_SIZE`
    fn split_at_nearest_large_page_boundary(self) -> (Frame, Frame) {
        if self.base % LARGE_PAGE_SIZE == 0 {
            (Frame::empty(), self)
        } else {
            let new_high_base = PAddr::from(round_up!(self.base.as_usize(), LARGE_PAGE_SIZE));
            let split_at = new_high_base - self.base;

            self.split_at(split_at.as_usize())
        }
    }

    /// Splits a given Frame into two, returns both as
    /// a (`low`, `high`) tuple.
    ///
    /// If `size` is bigger than `self`, `high`
    /// will be an `empty` frame.
    ///
    /// # Panics
    /// Panics if size is not a multiple of base page-size.
    pub fn split_at(self, size: usize) -> (Frame, Frame) {
        assert_eq!(size % BASE_PAGE_SIZE, 0);

        if size >= self.size() {
            (self, Frame::empty())
        } else {
            let low = Frame::new(self.base, size, self.affinity);
            let high = Frame::new(self.base + size, self.size() - size, self.affinity);

            (low, high)
        }
    }

    /// Represent the Frame as a slice of `T`.
    ///
    /// TODO: Bug (should we panic if we don't fit
    /// T's exactly?)
    #[allow(unused)]
    unsafe fn as_slice<T>(&self) -> Option<&[T]> {
        if self.size % core::mem::size_of::<T>() == 0 {
            Some(core::slice::from_raw_parts(
                self.kernel_vaddr().as_mut_ptr::<T>(),
                self.size / core::mem::size_of::<T>(),
            ))
        } else {
            None
        }
    }

    /// Represent the Frame as MaybeUinit<T>
    pub unsafe fn uninitialized<T>(self) -> &'static mut core::mem::MaybeUninit<T> {
        debug_assert!(core::mem::size_of::<T>() <= self.size);
        core::mem::transmute::<u64, &'static mut core::mem::MaybeUninit<T>>(
            self.kernel_vaddr().into(),
        )
    }

    /// Fill the page with many `T`'s.
    ///
    /// TODO: Think about this, should maybe return uninitialized
    /// instead?
    unsafe fn fill<T: Copy>(&mut self, pattern: T) -> bool {
        self.as_mut_slice::<T>().map_or(false, |obj| {
            for e in obj {
                *e = pattern;
            }
            true
        })
    }

    /// Size of the region (in 4K pages).
    pub fn base_pages(&self) -> usize {
        self.size / BASE_PAGE_SIZE
    }

    pub fn is_large_page_aligned(&self) -> bool {
        self.base % LARGE_PAGE_SIZE == 0
    }

    /// Size of the region (in bytes).
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn end(&self) -> PAddr {
        self.base + self.size
    }

    /// Zero the frame using `memset`.
    pub unsafe fn zero(&mut self) {
        self.fill(0);
    }

    /// The kernel virtual address for this region.
    pub fn kernel_vaddr(&self) -> VAddr {
        paddr_to_kernel_vaddr(self.base)
    }
}

pub struct IntoBasePageIter {
    frame: Frame,
}

impl core::iter::ExactSizeIterator for IntoBasePageIter {
    fn len(&self) -> usize {
        self.frame.size() / BASE_PAGE_SIZE
    }
}

impl core::iter::FusedIterator for IntoBasePageIter {}

impl core::iter::Iterator for IntoBasePageIter {
    // we will be counting with usize
    type Item = Frame;

    fn next(&mut self) -> Option<Self::Item> {
        use core::cmp::Ordering;
        match self.frame.size().cmp(&BASE_PAGE_SIZE) {
            Ordering::Greater => {
                let (low, high) = self.frame.split_at(BASE_PAGE_SIZE);
                self.frame = high;
                Some(low)
            }
            Ordering::Equal => {
                let mut last_page = Frame::empty();
                core::mem::swap(&mut last_page, &mut self.frame);
                Some(last_page)
            }
            Ordering::Less => None,
        }
    }
}

impl core::iter::IntoIterator for Frame {
    type Item = Frame;
    type IntoIter = IntoBasePageIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoBasePageIter { frame: self }
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Frame {{ 0x{:x} -- 0x{:x} (size = {}, pages = {}, node#{} }}",
            self.base,
            self.base + self.size,
            DataSize::from_bytes(self.size),
            self.base_pages(),
            self.affinity
        )
    }
}

pub trait PageTableProvider<'a> {
    fn allocate_pml4<'b>(&mut self) -> Option<&'b mut paging::PML4>;
    fn new_pdpt(&mut self) -> Option<paging::PML4Entry>;
    fn new_pd(&mut self) -> Option<paging::PDPTEntry>;
    fn new_pt(&mut self) -> Option<paging::PDEntry>;
    fn new_page(&mut self) -> Option<paging::PTEntry>;
}

#[allow(dead_code)]
pub struct NRKPageTableProvider;

impl NRKPageTableProvider {
    #[allow(dead_code)]
    pub const fn new() -> NRKPageTableProvider {
        NRKPageTableProvider
    }
}

impl<'a> PageTableProvider<'a> for NRKPageTableProvider {
    /// Allocate a PML4 table.
    fn allocate_pml4<'b>(&mut self) -> Option<&'b mut paging::PML4> {
        let kcb = kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();
        unsafe {
            fmanager
                .allocate_base_page()
                .map(|frame| {
                    let pml4: &'b mut [paging::PML4Entry; 512] =
                        transmute(paddr_to_kernel_vaddr(frame.base));
                    pml4
                })
                .ok()
        }
    }

    /// Allocate a new page directory and return a PML4 entry for it.
    fn new_pdpt(&mut self) -> Option<paging::PML4Entry> {
        let kcb = kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        fmanager
            .allocate_base_page()
            .map(|frame| {
                paging::PML4Entry::new(
                    frame.base,
                    paging::PML4Flags::P | paging::PML4Flags::RW | paging::PML4Flags::US,
                )
            })
            .ok()
    }

    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<paging::PDPTEntry> {
        let kcb = kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        fmanager
            .allocate_base_page()
            .map(|frame| {
                paging::PDPTEntry::new(
                    frame.base,
                    paging::PDPTFlags::P | paging::PDPTFlags::RW | paging::PDPTFlags::US,
                )
            })
            .ok()
    }

    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<paging::PDEntry> {
        let kcb = kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        fmanager
            .allocate_base_page()
            .map(|frame| {
                paging::PDEntry::new(
                    frame.base,
                    paging::PDFlags::P | paging::PDFlags::RW | paging::PDFlags::US,
                )
            })
            .ok()
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<paging::PTEntry> {
        let kcb = kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        fmanager
            .allocate_base_page()
            .map(|frame| {
                paging::PTEntry::new(
                    frame.base,
                    paging::PTFlags::P | paging::PTFlags::RW | paging::PTFlags::US,
                )
            })
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_iter() {
        let frame = Frame::new(PAddr::from(8 * 1024 * 1024), 4096 * 3, 0);
        let mut iter = frame.into_iter();
        assert_eq!(iter.len(), 3);

        let f1 = iter.next().unwrap();
        assert_eq!(f1.base, PAddr::from(8 * 1024 * 1024));
        assert_eq!(f1.size(), BASE_PAGE_SIZE);

        let f2 = iter.next().unwrap();
        assert_eq!(f2.base, PAddr::from(8 * 1024 * 1024 + 4096));
        assert_eq!(f2.size(), BASE_PAGE_SIZE);

        let f3 = iter.next().unwrap();
        assert_eq!(f3.base, PAddr::from(8 * 1024 * 1024 + 4096 + 4096));
        assert_eq!(f3.size(), BASE_PAGE_SIZE);

        let f4 = iter.next();
        assert_eq!(f4, None);

        let f4 = iter.next();
        assert_eq!(f4, None);

        assert_eq!(Frame::empty().into_iter().next(), None);
    }

    #[test]
    fn frame_split_at_nearest_large_page_boundary() {
        let f = Frame::new(PAddr::from(8 * 1024 * 1024), 4096 * 10, 0);
        assert_eq!(
            f.split_at_nearest_large_page_boundary(),
            (Frame::empty(), f)
        );

        let f = Frame::new(PAddr::from(LARGE_PAGE_SIZE - 5 * 4096), 4096 * 10, 0);
        let low = Frame::new(PAddr::from(LARGE_PAGE_SIZE - 5 * 4096), 4096 * 5, 0);
        let high = Frame::new(PAddr::from(LARGE_PAGE_SIZE), 4096 * 5, 0);
        assert_eq!(f.split_at_nearest_large_page_boundary(), (low, high));

        let f = Frame::new(PAddr::from(BASE_PAGE_SIZE), 4096 * 5, 0);
        assert_eq!(
            f.split_at_nearest_large_page_boundary(),
            (f, Frame::empty())
        );
    }

    #[test]
    fn frame_large_page_aligned() {
        let f = Frame::new(PAddr::from(0xf000), 4096 * 10, 0);
        assert!(!f.is_large_page_aligned());

        let f = Frame::new(PAddr::from(8 * 1024 * 1024), 4096 * 10, 0);
        assert!(f.is_large_page_aligned());
    }

    #[test]
    fn frame_split_at() {
        let f = Frame::new(PAddr::from(0xf000), 4096 * 10, 0);
        let (low, high) = f.split_at(4 * 4096);

        assert_eq!(low.base.as_u64(), 0xf000);
        assert_eq!(low.size(), 4 * 4096);
        assert_eq!(high.base.as_u64(), 0xf000 + 4 * 4096);
        assert_eq!(high.size(), 6 * 4096);
    }

    #[test]
    fn frame_base_pages() {
        let f = Frame::new(PAddr::from(0x1000), 4096 * 10, 0);
        assert_eq!(f.base_pages(), 10);
    }

    #[test]
    fn frame_size() {
        let f = Frame::new(PAddr::from(0xf000), 4096 * 10, 0);
        assert_eq!(f.size(), f.size);
        assert_eq!(f.size(), 4096 * 10);
    }

    #[test]
    fn frame_end() {
        let f = Frame::new(PAddr::from(0x1000), 4096 * 10, 0);
        assert_eq!(f.end(), PAddr::from(4096 * 10 + 0x1000));
    }

    #[test]
    #[should_panic]
    /// Frames should be aligned to BASE_PAGE_SIZE.
    fn frame_bad_alignment() {
        let _f = Frame::new(PAddr::from(usize::MAX), BASE_PAGE_SIZE, 0);
    }

    #[test]
    #[should_panic]
    /// Frames size should be multiple of BASE_PAGE_SIZE.
    fn frame_bad_size() {
        let _f = Frame::new(PAddr::from(0x1000), 0x13, 0);
    }

    #[test]
    fn size_formatting() {
        let ds = DataSize::from_bytes(LARGE_PAGE_SIZE);
        assert_eq!(ds, DataSize::MiB(2.0));

        let ds = DataSize::from_bytes(BASE_PAGE_SIZE);
        assert_eq!(ds, DataSize::KiB(4.0));

        let ds = DataSize::from_bytes(1024 * LARGE_PAGE_SIZE);
        assert_eq!(ds, DataSize::GiB(2.0));

        let ds = DataSize::from_bytes(usize::MIN);
        assert_eq!(ds, DataSize::Bytes(0.0));
    }

    #[test]
    fn layout_to_pages() {
        let l = unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE - 1, 0) };
        assert_eq!(KernelAllocator::layout_to_pages(l), (1, 0));

        let l = unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE, 0) };
        assert_eq!(KernelAllocator::layout_to_pages(l), (1, 0));

        let l = unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE + 1, 0) };
        assert_eq!(KernelAllocator::layout_to_pages(l), (2, 0));

        let l = unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE - 1, 0) };
        assert_eq!(
            KernelAllocator::layout_to_pages(l),
            (LARGE_PAGE_SIZE / BASE_PAGE_SIZE, 0)
        );

        let l = unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE, 0) };
        assert_eq!(KernelAllocator::layout_to_pages(l), (0, 1));

        let l = unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE + 1, 0) };
        assert_eq!(KernelAllocator::layout_to_pages(l), (1, 1));

        let l =
            unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE + 10 * BASE_PAGE_SIZE, 0) };
        assert_eq!(KernelAllocator::layout_to_pages(l), (10, 1));

        let l = unsafe {
            Layout::from_size_align_unchecked(2 * LARGE_PAGE_SIZE + 50 * BASE_PAGE_SIZE, 0)
        };
        assert_eq!(KernelAllocator::layout_to_pages(l), (50, 2));
    }

    #[test]
    fn allocator_selection() {
        let l = unsafe { Layout::from_size_align_unchecked(8, 8) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::Zone);

        let l = unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::Zone);

        let l = unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE + 1, BASE_PAGE_SIZE) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::Zone);

        let l = unsafe { Layout::from_size_align_unchecked(153424, 8) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::MemManager);

        let l = unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE - 1, LARGE_PAGE_SIZE) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::MemManager);

        let l = unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE, LARGE_PAGE_SIZE) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::MemManager);

        let l = unsafe { Layout::from_size_align_unchecked(LARGE_PAGE_SIZE + 1, LARGE_PAGE_SIZE) };
        assert_eq!(KernelAllocator::allocator_for(l), AllocatorType::MapBig);
    }
}
