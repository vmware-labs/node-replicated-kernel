use crate::alloc::string::ToString;
use core::alloc::{AllocErr, Layout};
use core::fmt;
use core::mem::transmute;

use arrayvec::ArrayVec;
use custom_error::custom_error;
use spin::Mutex;
use x86::bits64::paging;

pub mod buddy;
pub mod emem;
pub mod ncache;
pub mod tcache;

/// Re-export arch specific memory definitions
pub use crate::arch::memory::{
    paddr_to_kernel_vaddr, PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE,
};

use crate::prelude::*;
use slabmalloc::{ObjectPage, PageProvider};

pub use self::buddy::BuddyFrameAllocator as PhysicalMemoryAllocator;

custom_error! {pub AllocationError
    OutOfMemory{size: usize} = "Couldn't allocate {size}.",
    CacheExhausted = "Couldn't allocate bytes on this cache, need to re-grow first.",
    CacheFull = "Cache can't hold any more objects.",
    CantGrowFurther{count: usize} = "Cache full; only added {count} elements.",
}

/// Given `bytes` return the quantity in a human readable form.
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
/// TODO: This probably needs a more elaborate scheme in the future.
#[derive(Default)]
pub struct GlobalMemory {
    /// Holds a small amount of memory for every node.
    ///
    /// Used to initialize the rest of the GlobalMemory structures and cores.
    /// Not protected by locks since only the BSP core should ever try to access this.
    emem: ArrayVec<[emem::EarlyPhysicalManager; AFFINITY_REGIONS]>,

    /// All buddies in the system.
    buddies: ArrayVec<
        [CachePadded<(topology::NodeId, Mutex<&'static buddy::BuddyFrameAllocator>)>;
            MAX_PHYSICAL_REGIONS],
    >,

    /// All node-caches in the system.
    node_caches: ArrayVec<[CachePadded<Mutex<&'static ncache::NCache>>; AFFINITY_REGIONS]>,
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
            .expect("Need at least some frames");

        // 1. Construct the `emem`'s for all NUMA nodes:
        let mut cur_affinity = 0;
        for frame in memory.iter_mut() {
            // We have a frame that is big enough and witht he right affinity
            const FOUR_MIB: usize = 4 * 1024 * 1024;
            if frame.affinity == cur_affinity && frame.size() > FOUR_MIB {
                let (low, high) = frame.split_at(FOUR_MIB);
                info!("low {:?} high {:?}", low, high);
                cur_affinity += 1;
                debug_assert_eq!(low.size(), FOUR_MIB);

                *frame = high;
                gm.emem.push(emem::EarlyPhysicalManager::new(low));
            }
        }
        debug_assert_eq!(
            gm.emem.len(),
            max_affinity + 1,
            "Added early managers for all NUMA nodes"
        );

        // 2. Construct the buddies for all Frames
        // We get memory from the frame-local NUMA node (using previosuly created emem),
        // then we construct a buddy in the the uninitialized page memory
        // and stick it in `gm.buddies`
        for frame in memory {
            // TODO: Should pack multpile buddy on the same page as long as space permits
            // right now we have a page for every buddy (which is wasteful)
            let mut buddy_memory = gm.emem[frame.affinity as usize].allocate_base_page()?;
            let buddy_base_addr = buddy_memory.base;
            buddy_memory.zero(); // TODO this happens twice atm (see emem)
            let buddy_ptr = buddy_memory.uninitialized::<buddy::BuddyFrameAllocator>();
            let buddy: &'static mut buddy::BuddyFrameAllocator =
                buddy_ptr.write(buddy::BuddyFrameAllocator::new_with_frame(frame));
            debug_assert_eq!(&*buddy as *const _ as u64, buddy_base_addr.as_u64());

            gm.buddies
                .push(CachePadded::new((frame.affinity, Mutex::new(buddy))));
        }

        // 3. Construct an NCache for all nodes
        for affinity in 0..max_affinity {
            let mut ncache_memory = gm.emem[affinity].allocate_large_page()?;
            let ncache_memory_addr = ncache_memory.base;
            ncache_memory.zero(); // TODO this happens twice atm (see emem)

            let ncache_ptr = ncache_memory.uninitialized::<ncache::NCache>();
            let ncache: &'static mut ncache::NCache =
                ncache::NCache::init(ncache_ptr, affinity as topology::NodeId);
            debug_assert_eq!(&*ncache as *const _ as u64, ncache_memory_addr.as_u64());

            gm.node_caches.push(CachePadded::new(Mutex::new(ncache)));
        }

        // 4. Initial population of NCaches with memory from buddies
        // Ideally we fully exhaust all buddies and put everything in the NCache
        for (ncache_affinity, ref ncache) in gm.node_caches.iter().enumerate() {
            for buddy_cacheline in gm.buddies.iter() {
                let buddy_affinity = buddy_cacheline.0;
                let buddy = &buddy_cacheline.1;
                if buddy_affinity == ncache_affinity as u64 {
                    let buddy_locked = buddy.lock();
                    let ncache_locked = ncache.lock();

                    info!("{:?} {:?}", *buddy_locked, *ncache_locked);
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
    fn free(&self) -> usize;

    /// Memory (in bytes) that was handed out by this allocator
    /// and has not yet been reclaimed (memory currently in use).
    fn allocated(&self) -> usize;

    /// Total memory (in bytes) that is maintained by this allocator.
    fn size(&self) -> usize {
        self.free() + self.allocated()
    }

    /// Potential capacity (in bytes) that the allocator can maintain.
    ///
    /// Some allocator may have unlimited capacity, in that case
    /// they can return usize::max.
    ///
    /// e.g. this should hold `capacity() >= free() + allocated()`
    fn capacity(&self) -> usize;
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
            affinity: 0,
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
        debug_assert_eq!(base % BASE_PAGE_SIZE, 0);
        debug_assert_eq!(size % BASE_PAGE_SIZE, 0);

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

    /// Splits a given Frame into two, returns both.
    pub fn split_at(self, size: usize) -> (Frame, Frame) {
        assert_eq!(size % BASE_PAGE_SIZE, 0);
        assert!(size < self.size());

        let low = Frame::new(self.base, size, self.affinity);
        let high = Frame::new(self.base + size, self.size() - size, self.affinity);

        (low, high)
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
    unsafe fn uninitialized<T>(self) -> &'static mut core::mem::MaybeUninit<T> {
        debug_assert!(core::mem::size_of::<T>() <= self.size);
        core::mem::transmute::<u64, &'static mut core::mem::MaybeUninit<T>>(self.base.into())
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
                .allocate_frame(
                    Layout::new::<paging::Page>()
                        .align_to(BASE_PAGE_SIZE)
                        .unwrap(),
                )
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
                .allocate_frame(
                    Layout::new::<paging::Page>()
                        .align_to(BASE_PAGE_SIZE)
                        .unwrap(),
                )
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
                .allocate_frame(
                    Layout::new::<paging::Page>()
                        .align_to(BASE_PAGE_SIZE)
                        .unwrap(),
                )
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
                .allocate_frame(
                    Layout::new::<paging::Page>()
                        .align_to(BASE_PAGE_SIZE)
                        .unwrap(),
                )
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
                .allocate_frame(
                    Layout::new::<paging::Page>()
                        .align_to(BASE_PAGE_SIZE)
                        .unwrap(),
                )
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

pub struct BespinSlabsProvider;

unsafe impl Send for BespinSlabsProvider {}
unsafe impl Sync for BespinSlabsProvider {}

impl BespinSlabsProvider {
    pub const fn new() -> BespinSlabsProvider {
        BespinSlabsProvider
    }
}

impl<'a> PageProvider<'a> for BespinSlabsProvider {
    fn allocate_page(&mut self) -> Option<&'a mut ObjectPage<'a>> {
        let kcb = crate::kcb::get_kcb();
        let mut fmanager = kcb.mem_manager();

        unsafe {
            fmanager
                .allocate_frame(
                    Layout::new::<paging::Page>()
                        .align_to(BASE_PAGE_SIZE)
                        .unwrap(),
                )
                .map(|mut frame| {
                    frame.zero();
                    trace!("slabmalloc allocate frame.base = {:x}", frame.base);
                    let sp: &'a mut ObjectPage = transmute(paddr_to_kernel_vaddr(frame.base));
                    sp
                })
                .ok()
        }
    }

    fn release_page(&mut self, _p: &'a mut ObjectPage<'a>) {
        trace!("TODO!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
