//! TCache is a physical memory manager used to maintain a per-CPU page-cache.
//!
//! It has the following properties:
//!
//! - Fits in a 4 KiB page
//! - Can allocate and free 2 MiB and 4 KiB Frames very quickly using page-inlined stacks.
//! - Is not thread-safe (intended to be used on a single CPU)

use super::*;
use crate::memory::*;

/// A simple page-cache for a CPU thread.
///
/// Holds two stacks of pages for O(1) allocation/deallocation.
/// Implements the `ReapBackend` to give pages back.
pub struct TCache {
    /// Which thread this TCache is used on.
    thread: topology::ThreadId,
    /// Which node the memory in this cache is from.
    node: topology::NodeId,
    /// A vector of free, cached base-page addresses.
    base_page_addresses: arrayvec::ArrayVec<[PAddr; 254]>,
    /// A vector of free, cached large-page addresses.
    large_page_addresses: arrayvec::ArrayVec<[PAddr; 254]>,
}

impl TCache {
    pub fn new(thread: topology::ThreadId, node: topology::NodeId) -> TCache {
        TCache {
            thread,
            node,
            base_page_addresses: arrayvec::ArrayVec::new(),
            large_page_addresses: arrayvec::ArrayVec::new(),
        }
    }

    /// Populates a TCache with the memory from `frame`
    ///
    /// This works by repeatedly splitting the `frame`
    /// into smaller pages.
    fn populate(&mut self, frame: Frame) {
        let how_many_base_pages = if frame.size() < LARGE_PAGE_SIZE {
            // All pages in this frame are made base-pages
            frame.size() / BASE_PAGE_SIZE
        } else {
            // ~8% should be reserved as base-pages
            (frame.size() / BASE_PAGE_SIZE) * 8 / 100
        };

        let mut how_many_large_pages =
            ((frame.size() - (how_many_base_pages * BASE_PAGE_SIZE)) / LARGE_PAGE_SIZE) + 1;

        let (low_frame, mut large_page_aligned_frame) =
            frame.split_at_nearest_large_page_boundary();

        for base_page in low_frame.into_iter() {
            self.base_page_addresses
                .try_push(base_page.base)
                .expect("Can't push base-page in TCache");
        }

        // Add large pages
        info!("how_many_large_pages = {}", how_many_large_pages);
        while how_many_large_pages > 0 && large_page_aligned_frame.size() >= LARGE_PAGE_SIZE {
            let (large_page, rest) = large_page_aligned_frame.split_at(LARGE_PAGE_SIZE);
            self.large_page_addresses
                .try_push(large_page.base)
                .expect("Can't push large page in TCache");

            large_page_aligned_frame = rest;
            how_many_large_pages -= 1;
        }

        // Make rest base-pages
        for base_page in large_page_aligned_frame.into_iter() {
            self.base_page_addresses
                .try_push(base_page.base)
                .expect("Can't push base-pages");
        }
    }

    pub fn new_with_frame(
        thread: topology::ThreadId,
        node: topology::NodeId,
        mem: Frame,
    ) -> TCache {
        let mut tcache = TCache::new(thread, node);
        tcache.populate(mem);
        tcache
    }

    fn paddr_to_base_page(&self, pa: PAddr) -> Frame {
        Frame::new(pa, BASE_PAGE_SIZE, self.node)
    }

    fn paddr_to_large_page(&self, pa: PAddr) -> Frame {
        Frame::new(pa, LARGE_PAGE_SIZE, self.node)
    }

    /// How much free memory we can maintain.
    fn capacity(&self) -> usize {
        self.base_page_addresses.capacity() * BASE_PAGE_SIZE
            + self.large_page_addresses.capacity() * LARGE_PAGE_SIZE
    }

    /// How much free memory (bytes) we have left.
    fn free(&self) -> usize {
        self.base_page_addresses.len() * BASE_PAGE_SIZE
            + self.large_page_addresses.len() * LARGE_PAGE_SIZE
    }
}

impl PhysicalPageProvider for TCache {
    fn allocate_base_page(&mut self) -> Result<Frame, AllocationError> {
        if self.base_page_addresses.is_empty() {
            return Err(AllocationError::CacheExhausted);
        }

        let paddr = self
            .base_page_addresses
            .pop()
            .ok_or(AllocationError::OutOfMemory {
                size: BASE_PAGE_SIZE,
            })?;
        Ok(self.paddr_to_base_page(paddr))
    }

    fn release_base_page(&mut self, frame: Frame) -> Result<(), AllocationError> {
        assert_eq!(frame.size(), BASE_PAGE_SIZE);
        assert_eq!(frame.base % BASE_PAGE_SIZE, 0);
        assert_eq!(frame.affinity, self.node);

        self.base_page_addresses
            .try_push(frame.base)
            .map_err(|_e| AllocationError::CacheFull)
    }

    fn allocate_large_page(&mut self) -> Result<Frame, AllocationError> {
        if self.large_page_addresses.is_empty() {
            return Err(AllocationError::CacheExhausted);
        }

        let paddr = self
            .large_page_addresses
            .pop()
            .ok_or(AllocationError::OutOfMemory {
                size: LARGE_PAGE_SIZE,
            })?;
        Ok(self.paddr_to_large_page(paddr))
    }

    fn release_large_page(&mut self, frame: Frame) -> Result<(), AllocationError> {
        assert_eq!(frame.size(), LARGE_PAGE_SIZE);
        assert_eq!(frame.base % LARGE_PAGE_SIZE, 0);
        assert_eq!(frame.affinity, self.node);

        self.large_page_addresses
            .try_push(frame.base)
            .map_err(|_e| AllocationError::CacheFull)
    }
}

impl ReapBackend for TCache {
    /// Give base-pages back.
    fn reap_base_pages(&mut self, free_list: &mut [Option<Frame>]) {
        for insert in free_list.iter_mut() {
            if let Some(paddr) = self.base_page_addresses.pop() {
                *insert = Some(self.paddr_to_base_page(paddr));
            } else {
                // We don't have anything left in our cache
                break;
            }
        }
    }

    /// Give large-pages back.
    fn reap_large_pages(&mut self, free_list: &mut [Option<Frame>]) {
        for insert in free_list.iter_mut() {
            if let Some(paddr) = self.large_page_addresses.pop() {
                *insert = Some(self.paddr_to_large_page(paddr));
            } else {
                // We don't have anything left in our cache
                break;
            }
        }
    }
}

impl GrowBackend for TCache {
    fn base_page_capcacity(&self) -> usize {
        self.base_page_addresses.capacity() - self.base_page_addresses.len()
    }

    fn grow_base_pages(&mut self, free_list: &[Frame]) -> Result<(), AllocationError> {
        for frame in free_list {
            assert_eq!(frame.size(), BASE_PAGE_SIZE);
            assert_eq!(frame.base % BASE_PAGE_SIZE, 0);
            assert_eq!(frame.affinity, self.node);

            self.base_page_addresses
                .try_push(frame.base)
                .map_err(|_e| AllocationError::CacheFull)?;
        }
        Ok(())
    }

    fn large_page_capcacity(&self) -> usize {
        self.large_page_addresses.capacity() - self.large_page_addresses.len()
    }

    /// Add a slice of large-pages to `self`.
    fn grow_large_pages(&mut self, free_list: &[Frame]) -> Result<(), AllocationError> {
        for frame in free_list {
            assert_eq!(frame.size(), LARGE_PAGE_SIZE);
            assert_eq!(frame.base % LARGE_PAGE_SIZE, 0);
            assert_eq!(frame.affinity, self.node);

            self.large_page_addresses
                .try_push(frame.base)
                .map_err(|_e| AllocationError::CacheFull)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    /// TCache should be fit exactly within a base-page.
    #[test]
    fn tcache_is_page_sized() {
        assert_eq!(core::mem::size_of::<TCache>(), super::BASE_PAGE_SIZE);
    }

    /// TCache should be fit exactly within a base-page.
    #[test]
    fn tcache_populate() {
        let mut tcache =
            TCache::new_with_frame(1, 2, Frame::new(PAddr::from(0x2000), 10 * 0x1000, 4));
        assert_eq!(tcache.base_page_addresses.len(), 10);
        assert_eq!(tcache.large_page_addresses.len(), 0);

        let mut tcache = TCache::new_with_frame(
            1,
            2,
            Frame::new(
                PAddr::from((2 * 1024 * 1024) - 5 * 4096),
                (1024 * 1024 * 2) + 11 * 0x1000,
                4,
            ),
        );
        assert_eq!(tcache.base_page_addresses.len(), 11);
        assert_eq!(tcache.large_page_addresses.len(), 1);
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn tcache_invalid_base_frame_size() {
        let mut tcache = TCache::new(1, 4);
        tcache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1001, 4));
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn tcache_invalid_base_frame_align() {
        let mut tcache = TCache::new(1, 4);
        tcache.release_base_page(Frame::new(PAddr::from(0x2001), 0x1000, 4));
    }

    /// Can't add wrong affinity.
    #[test]
    #[should_panic]
    fn tcache_invalid_affinity() {
        let mut tcache = TCache::new(1, 1);
        tcache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4));
    }

    /// Test that reap interface of the TCache.
    #[test]
    fn tcache_reap() {
        let mut tcache = TCache::new(1, 4);

        // Insert some pages
        tcache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4));
        tcache.release_base_page(Frame::new(PAddr::from(0x3000), 0x1000, 4));

        tcache.release_large_page(Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 4));
        tcache.release_large_page(Frame::new(
            PAddr::from(LARGE_PAGE_SIZE * 4),
            LARGE_PAGE_SIZE,
            4,
        ));

        let mut free_list = [None];
        tcache.reap_base_pages(&mut free_list);
        assert_eq!(free_list[0].unwrap().base.as_u64(), 0x3000);
        assert_eq!(free_list[0].unwrap().size, 0x1000);
        assert_eq!(free_list[0].unwrap().affinity, 4);

        let mut free_list = [None, None, None];
        tcache.reap_base_pages(&mut free_list);
        assert_eq!(free_list[0].unwrap().base.as_u64(), 0x2000);
        assert_eq!(free_list[0].unwrap().size, 0x1000);
        assert_eq!(free_list[0].unwrap().affinity, 4);
        assert!(free_list[1].is_none());
        assert!(free_list[2].is_none());

        let mut free_list = [None, None];
        tcache.reap_large_pages(&mut free_list);
        assert_eq!(free_list[0].unwrap().base.as_usize(), LARGE_PAGE_SIZE * 4);
        assert_eq!(free_list[0].unwrap().size, LARGE_PAGE_SIZE);
        assert_eq!(free_list[0].unwrap().affinity, 4);
        assert_eq!(free_list[1].unwrap().base.as_usize(), LARGE_PAGE_SIZE);
        assert_eq!(free_list[1].unwrap().size, LARGE_PAGE_SIZE);
        assert_eq!(free_list[1].unwrap().affinity, 4);
    }

    /// Test that release and allocate works as expected.
    /// Also verify free memory reporting along the way.
    #[test]
    fn tcache_release_allocate() {
        let mut tcache = TCache::new(1, 2);

        // Insert some pages
        tcache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 2));
        tcache.release_base_page(Frame::new(PAddr::from(0x3000), 0x1000, 2));

        tcache.release_large_page(Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 2));
        tcache.release_large_page(Frame::new(
            PAddr::from(LARGE_PAGE_SIZE * 2),
            LARGE_PAGE_SIZE,
            2,
        ));
        assert_eq!(tcache.free(), 2 * BASE_PAGE_SIZE + 2 * LARGE_PAGE_SIZE);

        // Can we allocate
        let f = tcache.allocate_base_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), 0x3000);
        assert_eq!(f.size, 0x1000);
        assert_eq!(f.affinity, 2);

        let f = tcache.allocate_base_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), 0x2000);
        assert_eq!(f.size, 0x1000);
        assert_eq!(f.affinity, 2);

        let f = tcache
            .allocate_base_page()
            .expect_err("Can't allocate more than we gave it");

        assert_eq!(tcache.free(), 2 * LARGE_PAGE_SIZE);

        let f = tcache.allocate_large_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), (LARGE_PAGE_SIZE * 2) as u64);
        assert_eq!(f.size, LARGE_PAGE_SIZE);
        assert_eq!(f.affinity, 2);

        let f = tcache.allocate_large_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), LARGE_PAGE_SIZE as u64);
        assert_eq!(f.size, LARGE_PAGE_SIZE);
        assert_eq!(f.affinity, 2);

        assert_eq!(tcache.free(), 0);

        let f = tcache
            .allocate_base_page()
            .expect_err("Can't allocate more than we gave it");
    }
}
