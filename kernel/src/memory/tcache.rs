// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! TCache is a physical memory manager used to maintain a smallish page-cache.
//!
//! It has the following properties:
//!
//! - Fits in a 4 KiB page
//! - Can allocate and free 2 MiB and 4 KiB Frames very quickly using page-inlined stacks.
//! - Is not thread-safe (intended to be used on a single CPU)

use super::*;

/// A simple page-cache for a CPU thread.
///
/// Holds two stacks of pages for O(1) allocation/deallocation.
/// Implements the `ReapBackend` to give pages back.
pub struct TCache {
    /// Which node the memory in this cache is from.
    node: atopology::NodeId,
    /// A vector of free, cached base-page addresses.
    base_page_addresses: arrayvec::ArrayVec<[PAddr; 381]>,
    /// A vector of free, cached large-page addresses.
    large_page_addresses: arrayvec::ArrayVec<[PAddr; 128]>,
}

impl crate::kcb::MemManager for TCache {}

impl TCache {
    pub fn new(_thread: atopology::ThreadId, node: atopology::NodeId) -> TCache {
        TCache {
            node,
            base_page_addresses: arrayvec::ArrayVec::new(),
            large_page_addresses: arrayvec::ArrayVec::new(),
        }
    }

    pub fn new_with_frame(
        thread: atopology::ThreadId,
        node: atopology::NodeId,
        mem: Frame,
    ) -> TCache {
        let mut tcache = TCache::new(thread, node);
        tcache.populate(mem);
        tcache
    }

    /// Populates a TCache with the memory from `frame`
    ///
    /// This works by repeatedly splitting the `frame`
    /// into smaller pages.
    fn populate(&mut self, frame: Frame) {
        let mut how_many_large_pages = if frame.base_pages() > self.base_page_addresses.capacity() {
            let bytes_left_after_base_full =
                (frame.base_pages() - self.base_page_addresses.capacity()) * BASE_PAGE_SIZE;
            bytes_left_after_base_full / LARGE_PAGE_SIZE
        } else {
            // If this assert fails, we have to rethink what to return here
            debug_assert!(self.base_page_addresses.capacity() * BASE_PAGE_SIZE <= LARGE_PAGE_SIZE);
            1
        };
        if how_many_large_pages == 0 {
            // XXX: Try to have at least one large-page if possible
            how_many_large_pages = 1;
        }

        let (low_frame, mut large_page_aligned_frame) =
            frame.split_at_nearest_large_page_boundary();

        for base_page in low_frame.into_iter() {
            self.base_page_addresses
                .try_push(base_page.base)
                .expect("Can't add base-page from low_frame to TCache");
        }

        // Add large-pages
        while how_many_large_pages > 0 && large_page_aligned_frame.size() >= LARGE_PAGE_SIZE {
            let (large_page, rest) = large_page_aligned_frame.split_at(LARGE_PAGE_SIZE);
            self.large_page_addresses
                .try_push(large_page.base)
                .expect("Can't push large page in TCache");

            large_page_aligned_frame = rest;
            how_many_large_pages -= 1;
        }

        // Put the rest as base-pages
        let mut lost_pages = 0;
        for base_page in large_page_aligned_frame.into_iter() {
            match self.base_page_addresses.try_push(base_page.base) {
                Ok(()) => continue,
                Err(_) => {
                    lost_pages += 1;
                }
            }
        }

        if lost_pages > 0 {
            debug!(
                "TCache population lost {} of memory",
                DataSize::from_bytes(lost_pages * BASE_PAGE_SIZE)
            );
        }

        debug!(
            "TCache populated with {} base-pages and {} large-pages",
            self.base_page_addresses.len(),
            self.large_page_addresses.len()
        );
    }

    fn paddr_to_base_page(&self, pa: PAddr) -> Frame {
        Frame::new(pa, BASE_PAGE_SIZE, self.node)
    }

    fn paddr_to_large_page(&self, pa: PAddr) -> Frame {
        Frame::new(pa, LARGE_PAGE_SIZE, self.node)
    }
}

impl AllocatorStatistics for TCache {
    /// How much free memory (bytes) we have left.
    fn free(&self) -> usize {
        self.base_page_addresses.len() * BASE_PAGE_SIZE
            + self.large_page_addresses.len() * LARGE_PAGE_SIZE
    }

    /// How much free memory we can maintain.
    fn capacity(&self) -> usize {
        self.base_page_addresses.capacity() * BASE_PAGE_SIZE
            + self.large_page_addresses.capacity() * LARGE_PAGE_SIZE
    }

    fn allocated(&self) -> usize {
        0
    }

    fn size(&self) -> usize {
        0
    }

    fn internal_fragmentation(&self) -> usize {
        0
    }

    /// How many basepages we can allocate from the cache.
    fn free_base_pages(&self) -> usize {
        self.base_page_addresses.len()
    }

    /// How many large-pages we can allocate from the cache.
    fn free_large_pages(&self) -> usize {
        self.large_page_addresses.len()
    }
}

impl fmt::Debug for TCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TCache")
            .field("free", &self.free())
            .field("capacity", &self.capacity())
            .field("allocated", &self.allocated())
            .finish()
    }
}

impl PhysicalPageProvider for TCache {
    fn allocate_base_page(&mut self) -> Result<Frame, AllocationError> {
        let paddr = self
            .base_page_addresses
            .pop()
            .ok_or(AllocationError::CacheExhausted)?;
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
        let paddr = self
            .large_page_addresses
            .pop()
            .ok_or(AllocationError::CacheExhausted)?;
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
        let tcache = TCache::new_with_frame(1, 2, Frame::new(PAddr::from(0x2000), 10 * 0x1000, 4));
        assert_eq!(tcache.base_page_addresses.len(), 10);
        assert_eq!(tcache.large_page_addresses.len(), 0);

        let tcache = TCache::new_with_frame(
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
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1001, 4))
            .expect("release");
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn tcache_invalid_base_frame_align() {
        let mut tcache = TCache::new(1, 4);
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2001), 0x1000, 4))
            .expect("release");
    }

    /// Can't add wrong affinity.
    #[test]
    #[should_panic]
    fn tcache_invalid_affinity() {
        let mut tcache = TCache::new(1, 1);
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4))
            .expect("release");
    }

    /// Test that reap interface of the TCache.
    #[test]
    fn tcache_reap() {
        let mut tcache = TCache::new(1, 4);

        // Insert some pages
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4))
            .expect("release");
        tcache
            .release_base_page(Frame::new(PAddr::from(0x3000), 0x1000, 4))
            .expect("release");

        tcache
            .release_large_page(Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 4))
            .expect("release");
        tcache
            .release_large_page(Frame::new(
                PAddr::from(LARGE_PAGE_SIZE * 4),
                LARGE_PAGE_SIZE,
                4,
            ))
            .expect("release");

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
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 2))
            .expect("release");
        tcache
            .release_base_page(Frame::new(PAddr::from(0x3000), 0x1000, 2))
            .expect("release");

        tcache
            .release_large_page(Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 2))
            .expect("release");
        tcache
            .release_large_page(Frame::new(
                PAddr::from(LARGE_PAGE_SIZE * 2),
                LARGE_PAGE_SIZE,
                2,
            ))
            .expect("release");
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

        let _f = tcache
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

        let _f = tcache
            .allocate_base_page()
            .expect_err("Can't allocate more than we gave it");
    }
}
