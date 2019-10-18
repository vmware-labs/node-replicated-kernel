/*
use core::alloc::Layout;


use crate::memory::{Frame, PAddr, PhysicalAllocator, BASE_PAGE_SIZE};

#[derive(Debug)]
pub struct FrameAllocator {
    pub count: usize,
    regions: [Frame; FrameAllocator::MAX_FRAME_REGIONS],
}

impl PhysicalAllocator for FrameAllocator {
    fn init(&mut self) {
        self.sort_regions();
        self.clean_regions();
    }

    /// Adds a region of physical memory to our FrameAllocator.
    /// Note that `size` must be a multiple of BASE_PAGE_SIZE (4 KiB).
    unsafe fn add_memory(&mut self, region: Frame) -> bool {
        assert!(region.base.as_u64() > 0);
        assert!(region.size % BASE_PAGE_SIZE == 0);

        if self.count >= FrameAllocator::MAX_FRAME_REGIONS {
            error!("Not enough space in FrameAllocator. Increase MAX_FRAME_REGIONS!");
            return false;
        }

        self.regions[self.count] = region;
        self.count += 1;
        true
    }

    /// Allocate a region of memory.
    /// Note that `size` must be a multiple of BASE_PAGE_SIZE (4 KiB).
    unsafe fn allocate(&mut self, layout: Layout) -> Option<Frame> {
        let page_size: usize = BASE_PAGE_SIZE as usize;
        assert_eq!(layout.size() % page_size, 0);
        assert!(layout.align() <= BASE_PAGE_SIZE);

        let pages = layout.size() / BASE_PAGE_SIZE;
        for r in self.regions.iter_mut().rev() {
            if pages < r.base_pages() {
                let mut region = Frame::new(r.base, pages);
                r.base = r.base + layout.size();
                r.size -= pages * BASE_PAGE_SIZE;
                region.zero();
                assert!(region.base % BASE_PAGE_SIZE == 0);
                return Some(region);
            }
        }

        None
    }

    unsafe fn deallocate(&mut self, frame: Frame, _layout: Layout) {
        error!("Lost frame {:?}", frame);
    }

    fn print_info(&self) {
        info!("Found the following physical memory regions:");
        for i in 0..self.count {
            info!("Region {} = {:?}", i, self.regions[i]);
        }
    }
}

impl FrameAllocator {
    const MAX_FRAME_REGIONS: usize = 10;

    fn sort_regions(&mut self) {
        // Bubble sort the regions
        let mut n = self.count;
        while n > 0 {
            let mut newn = 0;
            let mut i = 1;

            while i < n {
                if self.regions[i - 1].base > self.regions[i].base {
                    let tmp: Frame = self.regions[i - 1];
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
        // Merge consecutive entries
        for i in 0..self.count {
            let end = self.regions[i].base + self.regions[i].size();
            if end == self.regions[i + 1].base {
                self.regions[i].size += self.regions[i + 1].size;

                // Mark region invalid (this is now merged with previous)
                self.regions[i + 1].base = PAddr::from(0xFFFFFFFFFFFFFFFFu64);
                self.regions[i + 1].size = 0;
            }

            self.sort_regions();
        }
    }
}
*/
