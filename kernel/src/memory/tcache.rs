//! TCache is a physical memory manager used to maintain a per-CPU page-cache.
//!
//! It has the following properties:
//!
//! - Fits in a 4 KiB page
//! - Can allocate and free 2 MiB and 4 KiB Frames very quickly using page-inlined stacks.
//! - Is not thread-safe, to be used strictly on a single CPU

use super::*;
use crate::memory::*;

/// A simple page-cache for a CPU thread.
///
/// Holds two stacks of pages for O(1) allocation/deallocation.
/// Implements the `ReapBackend` to give pages back.
struct TCache {
    /// Which thread this TCache is used on
    thread: topology::ThreadId,
    /// Which node the memory in this cache is from.
    node: topology::NodeId,
    /// A vector of free, cached base-page addresses
    base_page_addresses: arrayvec::ArrayVec<[PAddr; 254]>,
    /// A vector of free, cached large-page addresses
    large_page_addresses: arrayvec::ArrayVec<[PAddr; 254]>,
}

impl TCache {
    fn new(thread: topology::ThreadId, node: topology::NodeId) -> TCache {
        TCache {
            thread,
            node,
            base_page_addresses: arrayvec::ArrayVec::new(),
            large_page_addresses: arrayvec::ArrayVec::new(),
        }
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
        debug_assert_eq!(frame.size(), BASE_PAGE_SIZE);
        debug_assert_eq!(frame.base % BASE_PAGE_SIZE, 0);
        debug_assert_eq!(frame.affinity, self.node);

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
        debug_assert_eq!(frame.size(), LARGE_PAGE_SIZE);
        debug_assert_eq!(frame.base % LARGE_PAGE_SIZE, 0);
        debug_assert_eq!(frame.affinity, self.node);

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

#[cfg(test)]
mod test {
    use super::*;
    /// TCache should be fit exactly within a base-page.
    #[test]
    fn tcache_is_page_sized() {
        assert_eq!(core::mem::size_of::<TCache>(), super::BASE_PAGE_SIZE);
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
