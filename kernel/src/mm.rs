use core::alloc::Layout;
use core::mem::transmute;
use core::slice;

use core::fmt;

use x86::bits64::paging;

use arch::memory::{paddr_to_kernel_vaddr, PAddr, VAddr, BASE_PAGE_SIZE};
use slabmalloc::{ObjectPage, PageProvider};

const MAX_FRAME_REGIONS: usize = 10;

pub static mut FMANAGER: BumpFrameAllocator = BumpFrameAllocator {
    count: 0,
    regions: [PhysicalRegion::empty(); MAX_FRAME_REGIONS],
};

#[derive(Debug)]
pub struct BumpFrameAllocator {
    count: usize,
    regions: [PhysicalRegion; MAX_FRAME_REGIONS],
}

impl BumpFrameAllocator {
    /// Adds a region of physical memory to our BumpFrameAllocator.
    /// Note that `size` must be a multiple of BASE_PAGE_SIZE (4 KiB).
    pub fn add_region(&mut self, base: PAddr, size: u64) {
        assert!(base.as_u64() != 0);
        assert!(size % BASE_PAGE_SIZE as u64 == 0);

        if self.count >= MAX_FRAME_REGIONS {
            debug!("Not enough space in BumpFrameAllocator. Increase MAX_FRAME_REGIONS!");
            return;
        }

        self.regions[self.count] = PhysicalRegion::new(base, size / BASE_PAGE_SIZE as u64);
        self.count += 1;
    }

    /// Allocate a region of memory.
    /// Note that `size` must be a multiple of BASE_PAGE_SIZE (4 KiB).
    pub fn allocate_region(&mut self, layout: Layout) -> Option<PhysicalRegion> {
        let page_size: usize = BASE_PAGE_SIZE as usize;
        assert!(layout.size() % page_size == 0);
        // TODO: make sure alignment is ok

        let pages = (layout.size() / page_size) as u64;

        for r in self.regions.iter_mut().rev() {
            if pages < r.pages() {
                let region = PhysicalRegion::new(r.base, pages);
                r.base = r.base + layout.size();
                r.count -= pages;
                unsafe {
                    region.zero();
                }
                assert!(region.base % BASE_PAGE_SIZE == 0);

                return Some(region);
            }
        }

        None
    }

    fn sort_regions(&mut self) {
        // Bubble sort the regions
        let mut n = self.count;
        while n > 0 {
            let mut newn = 0;
            let mut i = 1;

            while i < n {
                if self.regions[i - 1].base > self.regions[i].base {
                    let tmp: PhysicalRegion = self.regions[i - 1];
                    self.regions[i - 1] = self.regions[i];
                    self.regions[i] = tmp;

                    newn = i;
                }
                i = i + 1;
            }
            n = newn;
        }
    }

    /// Make sure our regions are sorted and consecutive entires are merged.
    pub fn clean_regions(&mut self) {
        self.sort_regions();

        // Merge consecutive entries
        for i in 0..self.count {
            let end = self.regions[i].base + self.regions[i].size();
            if end == self.regions[i + 1].base {
                self.regions[i].count += self.regions[i + 1].pages();

                // Mark region invalid (this is now merged with previous)
                self.regions[i + 1].base = PAddr::from(0xFFFFFFFFFFFFFFFF);
                self.regions[i + 1].count = 0;
            }

            self.sort_regions();
        }
    }

    pub fn print_regions(&self) {
        debug!("self.count = {}", self.count);
        for i in 0..self.count {
            debug!("Region {} = {:?}", i, self.regions[i]);
            debug!(
                "Region PADDR base: {}; Region KVADDR base: {:?}",
                self.regions[i].base,
                self.regions[i].kernel_vaddr().as_ptr()
            );
        }
    }
}

/// Wrapper for a physical memory region
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct PhysicalRegion {
    /// Base address of physical region
    base: PAddr,
    /// Size of the region (in 4K pages)
    count: u64,
}

impl PhysicalRegion {
    const fn empty() -> PhysicalRegion {
        PhysicalRegion {
            base: PAddr::from_u64(0),
            count: 0,
        }
    }

    fn new(base: PAddr, pages: u64) -> PhysicalRegion {
        PhysicalRegion {
            base: base,
            count: pages,
        }
    }

    /// Size of the region (in 4K pages).
    pub fn pages(&self) -> u64 {
        self.count
    }

    /// Size of the region (in bytes).
    pub fn size(&self) -> u64 {
        self.count * BASE_PAGE_SIZE as u64
    }

    /// The kernel virtual address for this region.
    pub fn kernel_vaddr(&self) -> VAddr {
        paddr_to_kernel_vaddr(self.base)
    }

    /// Set the memory represented by this region to zero.
    unsafe fn zero(&self) {
        assert!(self.size() % 8 == 0);
        let buf: &mut [u64] = slice::from_raw_parts_mut(
            transmute(self.kernel_vaddr().as_ptr()),
            self.size() as usize,
        );
        for b in buf.iter_mut() {
            *b = 0 as u64;
        }
    }
}

impl fmt::Debug for PhysicalRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PhysicalRegion {{ 0x{:x} -- 0x{:x} (size = {}, pages = {} }}",
            self.base.as_u64(),
            self.base + self.size(),
            self.size(),
            self.pages()
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

pub struct BespinPageTableProvider;

impl BespinPageTableProvider {
    pub const fn new() -> BespinPageTableProvider {
        BespinPageTableProvider
    }
}

impl<'a> PageTableProvider<'a> for BespinPageTableProvider {
    /// Allocate a PML4 table.
    fn allocate_pml4<'b>(&mut self) -> Option<&'b mut paging::PML4> {
        unsafe {
            let f =
                FMANAGER.allocate_region(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE));
            f.map(|frame| {
                let pml4: &'b mut [paging::PML4Entry; 512] =
                    transmute(paddr_to_kernel_vaddr(frame.base));
                pml4
            })
        }
    }

    /// Allocate a new page directory and return a PML4 entry for it.
    fn new_pdpt(&mut self) -> Option<paging::PML4Entry> {
        unsafe {
            FMANAGER
                .allocate_region(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PML4Entry::new(
                        frame.base,
                        paging::PML4Entry::P | paging::PML4Entry::RW | paging::PML4Entry::US,
                    )
                })
        }
    }

    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<paging::PDPTEntry> {
        unsafe {
            FMANAGER
                .allocate_region(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PDPTEntry::new(
                        frame.base,
                        paging::PDPTEntry::P | paging::PDPTEntry::RW | paging::PDPTEntry::US,
                    )
                })
        }
    }

    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<paging::PDEntry> {
        unsafe {
            FMANAGER
                .allocate_region(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PDEntry::new(
                        frame.base,
                        paging::PDEntry::P | paging::PDEntry::RW | paging::PDEntry::US,
                    )
                })
        }
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<paging::PTEntry> {
        unsafe {
            FMANAGER
                .allocate_region(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PTEntry::new(
                        frame.base,
                        paging::PTEntry::P | paging::PTEntry::RW | paging::PTEntry::US,
                    )
                })
        }
    }
}

pub struct BespinSlabsProvider;

impl BespinSlabsProvider {
    pub const fn new() -> BespinSlabsProvider {
        BespinSlabsProvider
    }
}

impl<'a> PageProvider<'a> for BespinSlabsProvider {
    fn allocate_page(&mut self) -> Option<&'a mut ObjectPage<'a>> {
        let f = unsafe {
            FMANAGER.allocate_region(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
        };
        f.map(|frame| unsafe {
            debug!("slabmalloc allocate frame.base = {:x}", frame.base);
            let sp: &'a mut ObjectPage = transmute(paddr_to_kernel_vaddr(frame.base));
            sp
        })
    }

    fn release_page(&mut self, _p: &'a mut ObjectPage<'a>) {
        debug!("TODO!");
    }
}
