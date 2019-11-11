use crate::alloc::string::ToString;
use core::alloc::{AllocErr, GlobalAlloc, Layout};
use core::borrow::BorrowMut;
use core::fmt;
use core::intrinsics::{likely, unlikely};
use core::mem::transmute;
use core::ptr;

use arrayvec::ArrayVec;
use custom_error::custom_error;
use slabmalloc::ZoneAllocator;
use spin::Mutex;
use x86::bits64::paging;

pub mod buddy;
pub mod emem;
pub mod ncache;
pub mod tcache;

/// Re-export arch specific memory definitions
pub use crate::arch::memory::{
    kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE,
};

use crate::prelude::*;
use crate::round_up;

pub use self::buddy::BuddyFrameAllocator as PhysicalMemoryAllocator;

#[cfg(not(test))]
#[global_allocator]
static MEM_PROVIDER: KernelAllocator = KernelAllocator;

/// Implements the kernel memory allocation strategy.
struct KernelAllocator;

impl KernelAllocator {
    /// Transfers memory from the shared `from` allocator to a
    /// core-local `to` allocator.
    fn refill_local(from: Mutex<&dyn ReapBackend>, to: &mut dyn GrowBackend) {
        /*let mut free_list = [None, None];

        let from_locked = from.lock();
        from_locked.reap_base_pages(&mut free_list);
        drop(from_locked);

        to.grow_base_pages(free_list);*/
    }
}

/// Implementation of GlobalAlloc for the kernel.
///
/// The algorithm in alloc/dealloc should take care of allocating kernel objects of
/// various sizes and is responsible for balancing the memory between different
/// allocators.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Check if we have a KCB already (otherwise we can't do memory allocations)
        crate::kcb::try_get_kcb().map_or_else(
            || {
                error!("Trying to allocate {:?} without a KCB.", layout);
                ptr::null_mut()
            },
            |kcb| {
                // Distinguish between small and big allocations
                if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE && layout.size() != BASE_PAGE_SIZE
                {
                    // Allocate a small object on the zone allocator
                    let mut zone_allocator = kcb.zone_allocator.borrow_mut();
                    match zone_allocator.allocate(layout) {
                        Ok(ptr) => {
                            trace!("Allocated ptr={:p} layout={:?}", ptr, layout);
                            ptr.as_ptr()
                        }
                        Err(slabmalloc::AllocationError::OutOfMemory(l)) => {
                            let mut mem_manager = kcb.mem_manager();
                            let mut pmanager = mem_manager.borrow_mut();

                            if l.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                                let mut f = pmanager
                                    .allocate_base_page()
                                    .expect("TODO(error) handle refill-alloc failure");
                                f.zero();
                                let base_page_ptr: *mut slabmalloc::ObjectPage =
                                    f.uninitialized::<slabmalloc::ObjectPage>().as_mut_ptr();
                                zone_allocator
                                    .refill(l, transmute(base_page_ptr))
                                    .expect("TODO(error) Can't refill with base-page?");
                            } else {
                                let mut f = pmanager
                                    .allocate_large_page()
                                    .expect("TODO(error) handle refill-alloc failure");
                                f.zero();
                                let large_page_ptr: *mut slabmalloc::LargeObjectPage = f
                                    .uninitialized::<slabmalloc::LargeObjectPage>()
                                    .as_mut_ptr();
                                zone_allocator
                                    .refill_large(l, transmute(large_page_ptr))
                                    .expect("TODO(error) Can't refill with large-page?");
                            }
                            zone_allocator
                                .allocate(layout)
                                .expect("Allocation must succeed since we refilled.")
                                .as_ptr()
                        }
                        Err(e) => {
                            error!("Unable to allocate {:?} (got error {:?}).", layout, e);
                            ptr::null_mut()
                        }
                    }
                }
                // Here we allocate a large object (> 2 MiB), we need to multiple pages then map
                // them somewhere to make it contiguous.
                // The case where we need to map large objects should be rare (ideally never).
                else {
                    let mut mem_manager = kcb.mem_manager();
                    let f = if layout.size() <= BASE_PAGE_SIZE {
                        mem_manager.allocate_base_page()
                    } else if layout.size() <= LARGE_PAGE_SIZE {
                        mem_manager.allocate_large_page()
                    } else {
                        let fmt = format_size(layout.size());
                        unreachable!("allocate >= 2 MiB: {} {}", fmt.0, fmt.1)
                    };

                    let ptr = f.ok().map_or(core::ptr::null_mut(), |mut region| {
                        region.zero();
                        region.kernel_vaddr().as_mut_ptr()
                    });

                    trace!("allocated ptr={:p} {:?}", ptr, layout);
                    ptr
                }
            },
        )
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::kcb::try_get_kcb().map_or_else(
            || {
                unreachable!("Trying to deallocate {:p} {:?} without a KCB.", ptr, layout);
            },
            |kcb| {
                if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE && layout.size() != BASE_PAGE_SIZE
                {
                    let mut zone_allocator = kcb.zone_allocator.borrow_mut();
                    if likely(!ptr.is_null()) {
                        zone_allocator
                            .deallocate(ptr::NonNull::new_unchecked(ptr), layout)
                            .expect("Can't deallocate?");
                    } else {
                        warn!("Ignore null pointer deallocation");
                    }
                } else {
                    let kcb = crate::kcb::get_kcb();
                    let mut fmanager = kcb.mem_manager();
                    assert_eq!(layout.size(), BASE_PAGE_SIZE);
                    assert_eq!(layout.align(), BASE_PAGE_SIZE);

                    let frame = Frame::new(
                        kernel_vaddr_to_paddr(VAddr::from_u64(ptr as u64)),
                        layout.size(),
                        0,
                    );

                    fmanager
                        .release_base_page(frame)
                        .expect("Can't deallocate frame");
                }
            },
        );
    }
}

custom_error! {pub AllocationError
    OutOfMemory{size: usize} = "Couldn't allocate {size}.",
    CacheExhausted = "Couldn't allocate bytes on this cache, need to re-grow first.",
    CacheFull = "Cache can't hold any more objects.",
    CantGrowFurther{count: usize} = "Cache full; only added {count} elements.",
}

/// Given `bytes` return the quantity in a human readable form.
///
/// # Example
///
/// ```no-run
/// let ret = fromat_size(1024);
/// format!(w, "{:.2} {}", ret.1, ret.2);
/// ```
pub fn format_size(bytes: usize) -> (f64, &'static str) {
    if bytes < 1024 {
        (bytes as f64, "B")
    } else if bytes < (1024 * 1024) {
        (bytes as f64 / 1024.0, "KiB")
    } else if bytes < (1024 * 1024 * 1024) {
        (bytes as f64 / (1024 * 1024) as f64, "MiB")
    } else {
        (bytes as f64 / (1024 * 1024 * 1024) as f64, "GiB")
    }
}

/// How initial physical memory regions we support.
pub const MAX_PHYSICAL_REGIONS: usize = 64;

/// How many NUMA nodes we support in the system.
pub const AFFINITY_REGIONS: usize = 16;

/// Represents the global memory system in the kernel.
///
/// Has regions of memory that are maintained by a buddy allocator and
/// are partitioned to represent memory from just a single NUMA node.
///
/// Memory from those allocators then get pushed into the `ncache` that is supposed
/// to be fast and until they finally end up in the per-core TCache (which is found
/// in the core's KCB).
///
/// NCaches and Buddies can be accessed concurrently and are currently protected
/// by a simple spin-lock (for reclamation and allocation).
/// TODO(perf): This may need a more elaborate scheme in the future.
#[derive(Default)]
pub struct GlobalMemory {
    /// Holds a small amount of memory for every NUMA node.
    ///
    /// Used to initialize the system.
    pub(crate) emem: ArrayVec<[Mutex<emem::EarlyPhysicalManager>; AFFINITY_REGIONS]>,

    /// All physical mem. regions in the system are maintained by a buddy at the lowest level.
    pub(crate) buddies: ArrayVec<
        [CachePadded<(
            topology::NodeId,
            Mutex<&'static mut buddy::BuddyFrameAllocator>,
        )>; MAX_PHYSICAL_REGIONS],
    >,

    /// All node-caches in the system (one for every NUMA node).
    pub(crate) node_caches:
        ArrayVec<[CachePadded<Mutex<&'static mut ncache::NCache>>; AFFINITY_REGIONS]>,
}

impl GlobalMemory {
    /// Construct a new global memory object from a range of initial memory frames.
    /// This is typically invoked quite early (we're setting up support for memory allocation).
    ///
    /// We first chop off a small amount of memory from the frame to construct a EarlyPhysicalManager
    /// for every NUMA node.
    /// From the remaining frames we make buddy allocators.
    /// Then we construct node-caches (NCache) and populate them with memory from the buddies.
    ///
    /// When this completes we have a bunch of global NUMA aware memory allocators that
    /// are protected by spin-locks. `GlobalMemory` together with the `TCache` which is per-core
    /// is our physical memory allocation system.
    ///
    /// # Safety
    /// Pretty unsafe as we do lot of casting from frames to make space for our allocators.
    /// A client needs to ensure that our frames are valid memory, not being used anywhere yet.
    /// The good news is that we only invoke it once.
    pub unsafe fn new(
        mut memory: ArrayVec<[Frame; MAX_PHYSICAL_REGIONS]>,
    ) -> Result<GlobalMemory, AllocationError> {
        debug_assert!(!memory.is_empty());
        let mut gm = GlobalMemory::default();

        let max_affinity: usize = memory
            .iter()
            .map(|f| f.affinity as usize)
            .max()
            .expect("Need at least some frames")
            + 1;

        // 1. Construct the `emem`'s for all NUMA nodes:
        let mut cur_affinity = 0;
        for frame in memory.iter_mut() {
            // We have a frame that is big enough and with the right affinity
            const FOUR_MIB: usize = 4 * 1024 * 1024;
            if frame.affinity == cur_affinity && frame.size() > FOUR_MIB {
                let (low, high) = frame.split_at(FOUR_MIB);
                cur_affinity += 1;
                debug_assert_eq!(low.size(), FOUR_MIB);

                *frame = high;
                gm.emem
                    .push(Mutex::new(emem::EarlyPhysicalManager::new(low)));
            }
        }
        debug_assert_eq!(
            gm.emem.len(),
            max_affinity,
            "Added early managers for all NUMA nodes"
        );

        // 2. Construct the buddies for all Frames
        //
        // TODO(wasteful): We need to make sure that frame sizes are
        // powers of two and we don't just chop away lots of
        // memory in the buddy (ideally the buddy does the split
        // and returns the rest of the frame to us).
        //
        // We get memory from the frame-local NUMA node (using previosuly created emem),
        // then we construct a buddy in the the uninitialized page memory
        // and stick it in `gm.buddies`
        for frame in memory {
            // TODO(efficiency): Should pack multpile buddy on the same page as long as space permits
            // right now we have a page for every buddy (which is wasteful)
            let mut buddy_memory = gm.emem[frame.affinity as usize]
                .lock()
                .allocate_base_page()?;
            let buddy_base_addr: PAddr = buddy_memory.base;
            buddy_memory.zero(); // TODO(perf) this happens twice atm (see emem)?
            let buddy_vptr = buddy_memory.uninitialized::<buddy::BuddyFrameAllocator>();
            let buddy: &'static mut buddy::BuddyFrameAllocator =
                buddy_vptr.write(buddy::BuddyFrameAllocator::new_with_frame(frame));
            debug_assert_eq!(
                &*buddy as *const _ as u64,
                paddr_to_kernel_vaddr(buddy_base_addr).as_u64()
            );

            gm.buddies
                .push(CachePadded::new((frame.affinity, Mutex::new(buddy))));
        }

        // 3. Construct an NCache for all nodes
        for affinity in 0..max_affinity {
            let mut ncache_memory = gm.emem[affinity].lock().allocate_large_page()?;
            let ncache_memory_addr: PAddr = ncache_memory.base;
            ncache_memory.zero(); // TODO(perf) this happens twice atm (see emem)?

            let ncache_ptr = ncache_memory.uninitialized::<ncache::NCache>();
            let ncache: &'static mut ncache::NCache =
                ncache::NCache::init(ncache_ptr, affinity as topology::NodeId);
            debug_assert_eq!(
                &*ncache as *const _ as u64,
                paddr_to_kernel_vaddr(ncache_memory_addr).as_u64()
            );

            gm.node_caches.push(CachePadded::new(Mutex::new(ncache)));
        }

        // 4. Initial population of NCaches with memory from buddies
        // Ideally we fully exhaust all buddies and put everything in the NCache
        // The one thing we have to decide is how much goes into 4 KiB pages
        // and how much goes into 2 MiB pages; ideally we use 2 MiB for
        // almost everything so we aim for ~8% 4K pages of the total node memory
        //
        // TODO(perf): we really don't have to allocate from the buddy, just insert
        // directly in NCache
        for (ncache_affinity, ref ncache) in gm.node_caches.iter().enumerate() {
            for buddy_cacheline in gm.buddies.iter() {
                let buddy_affinity = buddy_cacheline.0;
                let buddy = &buddy_cacheline.1;
                if buddy_affinity == ncache_affinity as u64 {
                    let mut buddy_locked = buddy.lock();
                    let mut ncache_locked = ncache.lock();

                    let how_many_base_pages = if buddy_locked.free() < LARGE_PAGE_SIZE {
                        // All pages in this frame are made base-pages
                        buddy_locked.free() / BASE_PAGE_SIZE
                    } else {
                        // ~8% should be reserved as base-pages
                        (buddy_locked.free() / BASE_PAGE_SIZE) * 8 / 100
                    };

                    let how_many_large_pages = (buddy_locked.free()
                        - (how_many_base_pages * BASE_PAGE_SIZE))
                        / LARGE_PAGE_SIZE;

                    trace!(
                        "Trying to add {} base-pages, {} large-pages to NCache",
                        how_many_base_pages,
                        how_many_large_pages
                    );
                    for cnt in 0..how_many_base_pages {
                        match buddy_locked.allocate_frame(Layout::from_size_align_unchecked(
                            BASE_PAGE_SIZE,
                            BASE_PAGE_SIZE,
                        )) {
                            Ok(frame) => {
                                ncache_locked.grow_base_pages(&[frame])?;
                                //debug!("gave base page to ncache {:?}", frame);
                            }
                            Err(AllocationError::OutOfMemory { size: x }) => {
                                debug_assert_eq!(x, BASE_PAGE_SIZE);
                                break;
                            }
                            Err(e) => {
                                error!(
                                    "Unexpcted error while filling NCache from {:?} (error was {:?})",
                                    *buddy_locked, e
                                );
                                break;
                            }
                        };
                    }

                    for cnt in 0..how_many_large_pages {
                        match buddy_locked.allocate_frame(Layout::from_size_align_unchecked(
                            LARGE_PAGE_SIZE,
                            LARGE_PAGE_SIZE,
                        )) {
                            Ok(frame) => {
                                ncache_locked.grow_large_pages(&[frame])?;
                                //debug!("gave large page to ncache {:?}", frame);
                            }
                            Err(AllocationError::OutOfMemory { size: x }) => {
                                debug_assert_eq!(x, LARGE_PAGE_SIZE);
                                break;
                            }
                            Err(e) => {
                                error!(
                                    "Unexpcted error while filling NCache from {:?} (error was {:?})",
                                    *buddy_locked, e
                                );
                                break;
                            }
                        };
                    }

                    debug!("{:?} {:?}", *buddy_locked, *ncache_locked);
                }
            }
        }

        Ok(gm)
    }
}

/// A trait to allocate and release physical pages from an allocator.
pub trait PhysicalPageProvider {
    /// Allocate a `BASE_PAGE_SIZE` for the given architecture from the allocator.
    fn allocate_base_page(&mut self) -> Result<Frame, AllocationError>;
    /// Release a `BASE_PAGE_SIZE` for the given architecture back to the allocator.
    fn release_base_page(&mut self, f: Frame) -> Result<(), AllocationError>;

    /// Allocate a `LARGE_PAGE_SIZE` for the given architecture from the allocator.
    fn allocate_large_page(&mut self) -> Result<Frame, AllocationError>;
    /// Release a `LARGE_PAGE_SIZE` for the given architecture back to the allocator.
    fn release_large_page(&mut self, f: Frame) -> Result<(), AllocationError>;
}

/// The backend implementation necessary to implement if we want a client to be
/// able to grow our allocator by providing a list of frames.
pub trait GrowBackend {
    /// How much capacity we have to add base pages.
    fn base_page_capcacity(&self) -> usize;

    /// Add a slice of base-pages to `self`.
    fn grow_base_pages(&mut self, free_list: &[Frame]) -> Result<(), AllocationError>;

    /// How much capacity we have to add large pages.
    fn large_page_capcacity(&self) -> usize;

    /// Add a slice of large-pages to `self`.
    fn grow_large_pages(&mut self, free_list: &[Frame]) -> Result<(), AllocationError>;
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
    unsafe fn allocate_frame(&mut self, layout: Layout) -> Result<Frame, AllocationError>;

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
    pub affinity: topology::NodeId,
}

impl Frame {
    /// Make a new Frame at `base` with `size`
    pub const fn const_new(base: PAddr, size: usize, node: topology::NodeId) -> Frame {
        Frame {
            base: base,
            size: size,
            affinity: node,
        }
    }

    /// Create a new Frame given a PAddr range (from, to)
    pub fn from_range(range: (PAddr, PAddr), node: topology::NodeId) -> Frame {
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
    pub fn new(base: PAddr, size: usize, node: topology::NodeId) -> Frame {
        assert_eq!(base % BASE_PAGE_SIZE, 0);
        assert_eq!(size % BASE_PAGE_SIZE, 0);

        Frame {
            base: base,
            size: size,
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

    /// Represent the Frame as a `*mut T`.
    fn as_mut_ptr<T>(self) -> *mut T {
        debug_assert!(core::mem::size_of::<T>() <= self.size);
        self.base.as_u64() as *mut T
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
            for i in 0..obj.len() {
                obj[i] = pattern;
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
        if self.frame.size() > BASE_PAGE_SIZE {
            let (low, high) = self.frame.split_at(BASE_PAGE_SIZE);
            self.frame = high;
            Some(low)
        } else if self.frame.size() == BASE_PAGE_SIZE {
            let mut last_page = Frame::empty();
            core::mem::swap(&mut last_page, &mut self.frame);
            Some(last_page)
        } else {
            None
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
        let (size_formatted, unit) = format_size(self.size);
        write!(
            f,
            "Frame {{ 0x{:x} -- 0x{:x} (size = {:.2} {}, pages = {}, node#{} }}",
            self.base,
            self.base + self.size,
            size_formatted,
            unit,
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
pub struct BespinPageTableProvider;

impl BespinPageTableProvider {
    #[allow(dead_code)]
    pub const fn new() -> BespinPageTableProvider {
        BespinPageTableProvider
    }
}

impl<'a> PageTableProvider<'a> for BespinPageTableProvider {
    /// Allocate a PML4 table.
    fn allocate_pml4<'b>(&mut self) -> Option<&'b mut paging::PML4> {
        let kcb = crate::kcb::get_kcb();
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
        let kcb = crate::kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        unsafe {
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
    }

    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<paging::PDPTEntry> {
        let kcb = crate::kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        unsafe {
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
    }

    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<paging::PDEntry> {
        let kcb = crate::kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        unsafe {
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
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<paging::PTEntry> {
        let kcb = crate::kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        unsafe {
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
        let f = Frame::new(PAddr::from(core::usize::MAX), BASE_PAGE_SIZE, 0);
    }

    #[test]
    #[should_panic]
    /// Frames size should be multiple of BASE_PAGE_SIZE.
    fn frame_bad_size() {
        let f = Frame::new(PAddr::from(0x1000), 0x13, 0);
    }

    #[test]
    fn size_formatting() {
        let (a, unit) = format_size(LARGE_PAGE_SIZE);
        assert_eq!(unit, "MiB");
        assert_eq!(a, 2.0);

        let (a, unit) = format_size(BASE_PAGE_SIZE);
        assert_eq!(unit, "KiB");
        assert_eq!(a, 4.0);

        let (a, unit) = format_size(core::usize::MAX);
        assert_eq!(unit, "GiB");

        let (a, unit) = format_size(core::usize::MIN);
        assert_eq!(unit, "B");
    }
}
