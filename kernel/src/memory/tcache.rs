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
    base_page_addresses: arrayvec::ArrayVec<PAddr, 381>,
    /// A vector of free, cached large-page addresses.
    large_page_addresses: arrayvec::ArrayVec<PAddr, 128>,
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
}
