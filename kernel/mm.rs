use core::prelude::*;
use core::slice;
use core::mem::{transmute, size_of};

use std::fmt;

use x86::paging::{PML4, PML4Entry};

use ::arch::memory::{VAddr, PAddr, BASE_PAGE_SIZE, paddr_to_kernel_vaddr, kernel_vaddr_to_paddr};
use mutex::{Mutex};

const MAX_FRAME_REGIONS: usize = 10;

pub static fmanager: Mutex<FrameManager> =
    mutex!(FrameManager { count: 0, regions: [MemoryRegion{base: 0, size: 0, index: 0}; MAX_FRAME_REGIONS] });

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
            log!("Not enough space in FrameManager. Increase MAX_FRAME_REGIONS!");
            return;
        }

        self.regions[self.count].base = base;
        self.regions[self.count].size = size;
        self.count += 1;
    }

    pub fn allocate_frame(&mut self, size: u64) -> Option<Frame> {
        assert!(size % BASE_PAGE_SIZE == 0);
        //log!("regions = {:?}", self.regions);

        for r in &mut self.regions.iter_mut().rev() {
            if size < r.size - r.index {
                (*r).index += size;
                let f = Frame { base: (r.base+r.size) - r.index, size: size };

                //log!("f = {:?}",f);
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
            log!("Region {} = {:?}", i, self.regions[i]);
        }
    }

    /// XXX: should not be here
    pub fn allocate_pml4<'b>(&mut self) -> Option<&'b mut PML4> {
        let f = self.allocate_frame(BASE_PAGE_SIZE);
        match f {
            Some(frame) => {
                unsafe {
                    let pml4: &'b mut [PML4Entry; 512] = unsafe {
                        transmute(paddr_to_kernel_vaddr(frame.base))
                    };
                    log!("allocate pml4 at 0x{:x}", frame.base);
                    Some(pml4)
                }
            }
            None => None
        }
    }
}