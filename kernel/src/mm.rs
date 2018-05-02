use core::slice;
use core::mem::{transmute};

use std::fmt;

use x86::bits64::paging;

use ::arch::memory::{PAddr, BASE_PAGE_SIZE, paddr_to_kernel_vaddr};
use slabmalloc::{SlabPageProvider, SlabPage};

const MAX_FRAME_REGIONS: usize = 10;

pub static mut fmanager: FrameManager =
    FrameManager { count: 0, regions: [MemoryRegion{base: 0, size: 0, index: 0}; MAX_FRAME_REGIONS] };

#[derive(Debug)]
pub struct FrameManager {
    count: usize,
    regions: [ MemoryRegion; MAX_FRAME_REGIONS ]
}

/// Represents a physical region of memory.
pub struct Frame {
    pub base: PAddr,
    pub size: u64,
}

impl Frame {
    fn zero(&self) {
        let buf: &mut [u8] = unsafe {
            slice::from_raw_parts_mut(
                transmute(paddr_to_kernel_vaddr(self.base)),
                self.size as usize)
        };

        for b in buf.iter_mut() {
            *b = 0 as u8;
        }
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Frame: 0x{:x} -- 0x{:x} (size = {})", self.base, self.base+self.size, self.size)
    }
}

/// Represents a physical region of memory.
#[derive(Clone, Copy)]
struct MemoryRegion {
    base: PAddr, ///< Physical base address of the region.
    size: u64, ///< Size of the region.
    index: u64
}

impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MemoryRegion: 0x{:x} -- 0x{:x} (size = {})\n", self.base, self.base+self.size, self.size)
    }
}


impl FrameManager {

    pub fn new() -> FrameManager {
        FrameManager { count: 0, regions: [MemoryRegion{base: 0, size: 0, index: 0}; MAX_FRAME_REGIONS] }
    }

    /// Adds a region of physical memory to our FrameManager.
    pub fn add_region(&mut self, base: PAddr, size: u64) {
        if self.count >= MAX_FRAME_REGIONS {
            slog!("Not enough space in FrameManager. Increase MAX_FRAME_REGIONS!");
            return;
        }

        self.regions[self.count].base = base;
        self.regions[self.count].size = size;
        self.count += 1;
    }

    pub fn allocate_frame(&mut self, size: u64) -> Option<Frame> {
        assert!(size % BASE_PAGE_SIZE == 0);
        //slog!("regions = {:?}", self.regions);

        for r in &mut self.regions.iter_mut().rev() {
            if size < r.size - r.index {
                (*r).index += size;
                let f = Frame { base: (r.base+r.size) - r.index, size: size };

                //slog!("f = {:?}",f);
                f.zero();
                return Some(f);
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
                if self.regions[i-1].base > self.regions[i].base {
                    let tmp: MemoryRegion = self.regions[i-1];
                    self.regions[i-1] = self.regions[i];
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
            let end = self.regions[i].base + self.regions[i].size;
            if end == self.regions[i+1].base {

                self.regions[i].size += self.regions[i+1].size;

                // Mark region invalid (this is now merged with previous)
                self.regions[i+1].base = 0xFFFFFFFFFFFFFFFF;
                self.regions[i+1].size = 0;
            }

            self.sort_regions();
        }
    }

    pub fn print_regions(&self) {
        for i in 0..self.count {
            slog!("Region {} = {:?}", i, self.regions[i]);
        }
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
            let f = fmanager.allocate_frame(BASE_PAGE_SIZE);
            f.map(|frame| {
                let pml4: &'b mut [paging::PML4Entry; 512] = transmute(paddr_to_kernel_vaddr(frame.base));
                pml4
            })
        }
    }

    /// Allocate a new page directory and return a PML4 entry for it.
    fn new_pdpt(&mut self) -> Option<paging::PML4Entry> {
        unsafe {
            fmanager.allocate_frame(BASE_PAGE_SIZE).map(|frame| {
                paging::PML4Entry::new(frame.base, paging::PML4Entry::P | paging::PML4Entry::RW | paging::PML4Entry::US)
            })
        }
    }


    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<paging::PDPTEntry> {
        unsafe {
            fmanager.allocate_frame(BASE_PAGE_SIZE).map(|frame| {
                paging::PDPTEntry::new(frame.base, paging::PDPTEntry::P | paging::PDPTEntry::RW | paging::PDPTEntry::US)
            })
        }
    }


    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<paging::PDEntry> {
        unsafe {
            fmanager.allocate_frame(BASE_PAGE_SIZE).map(|frame| {
                paging::PDEntry::new(frame.base, paging::PDEntry::P | paging::PDEntry::RW | paging::PDEntry::US)
            })
        }
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<paging::PTEntry> {
        unsafe {
            fmanager.allocate_frame(BASE_PAGE_SIZE).map(|frame| {
                paging::PTEntry::new(frame.base, paging::PTEntry::P | paging::PTEntry::RW | paging::PTEntry::US)
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

impl<'a> SlabPageProvider<'a> for BespinSlabsProvider {

    fn allocate_slabpage(&mut self) -> Option<&'a mut SlabPage<'a>> {
        let f = unsafe { fmanager.allocate_frame(BASE_PAGE_SIZE) };
        f.map(|frame| {
            unsafe {
                let sp: &'a mut SlabPage = transmute(paddr_to_kernel_vaddr(frame.base));
                sp
            }
        })
    }

    fn release_slabpage(&mut self, p: &'a mut SlabPage<'a>) {
        slog!("TODO!");
    }

}