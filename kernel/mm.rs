use ::arch::memory::{VAddr, PAddr, BASE_PAGE_SIZE};
use multiboot;

const KERNEL_BASE: u64 = 0xFFFFFFFF80000000;
const MAX_FRAME_REGIONS: usize = 5;

#[derive(Debug)]
pub struct FrameManager {
    count: usize,
    regions: [ MemoryRegion; MAX_FRAME_REGIONS ]
}

/// Represents a physical region of memory.
#[derive(Debug)]
pub struct Frame {
    pub base: PAddr,
    pub size: u64,
}

/// Internal bookkeeping about regions of memory.
#[derive(Debug, Copy)]
struct MemoryRegion {
    base: PAddr, ///< Physical base address of the region.
    size: u64, ///< Size of the region.
    index: u64 
}

/// Translate a kernel 'virtual' address to the physical address of the memory.
pub fn kernel_vaddr_to_paddr(v: VAddr) -> PAddr {
    v - KERNEL_BASE
}

/// Translate a physical memory address into a kernel addressable location.
pub fn paddr_to_kernel_vaddr(p: PAddr) -> VAddr {
    p + KERNEL_BASE
}


impl FrameManager {

    pub fn new() -> FrameManager {
        FrameManager { count: 0, regions: [MemoryRegion{base: 0, size: 0, index: 0}; MAX_FRAME_REGIONS] }
    }

    /// Adds a multiboot region to our FrameManager.
    pub fn add_multiboot_region(&mut self, base: PAddr, size: u64, mtype: multiboot::MemType) {
        if mtype == multiboot::MemType::Unusable {
            log!("ignore unusable memory",);
            return
        }

        if self.count >= MAX_FRAME_REGIONS {
            log!("Not enough space in FrameManager. Increase MAX_FRAME_REGIONS!");
            return;
        }

        self.regions[self.count].base = base;
        self.regions[self.count].size = size;
        self.count += 1;
    }

    pub fn allocate_frame(&mut self) -> Frame {
        let page_size = BASE_PAGE_SIZE;
        
        let mut i = self.count;
        while i > 0 {
            if (self.regions[i].index + page_size) < (self.regions[i].base + self.regions[i].size) {
                let f = Frame { base: self.regions[i].base + self.regions[i].index, size: page_size };
                self.regions[i].index += page_size;
                return f;
            }

            i -= 1;
        }

        // XXX: error handling
        Frame {base: 0, size: 0}
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
    /// TODO: Can we have overlapping entries?
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

}