//! NCache is a physical memory manager used to maintain a per-NUMA node memory.
//!
//! It can be a cache but should be big enough to contain all memory on the node.
//!
//! It has the following properties:
//!
//! - Fits in a 2 MiB page
//! - Can allocate and free 2 MiB and 4 KiB Frames very quickly using stacks.
//! - Is not thread-safe, need to wrap it in a Mutex (ideall we have two
//!   interior Mutex for base-page and large-page arrays but that's problematic
//!   because our traits are currently using &mut self).
//! - TODO: Should have a directory-style index to put a list of 2 MiB, 4KiB
//!   pages stack into an entry within the NCache list.
//!
//!

use core::fmt;
use core::mem::MaybeUninit;

use super::*;
use crate::memory::*;

/// A simple page-cache for a NUMA node.
///
/// Holds two stacks of pages for O(1) allocation/deallocation.
/// Implements the `GrowBackend` to hand pages out.
pub struct NCache {
    /// Which node the memory in this cache is from.
    node: topology::NodeId,
    /// A vector of free, cached base-page addresses
    base_page_addresses: arrayvec::ArrayVec<[PAddr; 65536]>,
    /// A vector of free, cached large-page addresses
    large_page_addresses: arrayvec::ArrayVec<[PAddr; 65536]>,
    // A list of pages which are full of addresses of base pages.
    //base_page_index: arrayvec::ArrayVec<[PAddr; 32768]>,
    // A list of pages which are full of addresses of large pages.
    //large_page_index: arrayvec::ArrayVec<[PAddr; 32768]>,
}

impl NCache {
    pub fn new(node: topology::NodeId) -> NCache {
        NCache {
            node,
            base_page_addresses: arrayvec::ArrayVec::new(),
            large_page_addresses: arrayvec::ArrayVec::new(),
            //base_page_index: arrayvec::ArrayVec::new(),
            //large_page_index: arrayvec::ArrayVec::new(),
        }
    }

    /// Initialize an uninitialized NCache and return it.
    pub fn init<'a>(ncache: &'a mut MaybeUninit<NCache>, node: topology::NodeId) -> &'a mut NCache {
        unsafe {
            (*(ncache.as_mut_ptr())).node = node;
            ncache.get_mut()
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

impl fmt::Debug for NCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (free, free_unit) = super::format_size(self.free());
        let (capacity, capacity_unit) = super::format_size(self.capacity());

        write!(
            f,
            "NCache {{ free: {:.2} {}, capacity: {:.2} {}, affinity: {} }}",
            free, free_unit, capacity, capacity_unit, self.node
        )
    }
}

impl PhysicalPageProvider for NCache {
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

impl GrowBackend for NCache {
    fn base_page_capcacity(&self) -> usize {
        self.base_page_addresses.capacity()
    }

    fn grow_base_pages(&mut self, free_list: &[Frame]) -> Result<(), AllocationError> {
        for (idx, insert) in free_list.iter().enumerate() {
            match self.release_base_page(*insert) {
                Err(_) => return Err(AllocationError::CantGrowFurther { count: idx }),
                _ => {}
            }
        }
        Ok(())
    }

    fn large_page_capcacity(&self) -> usize {
        self.large_page_addresses.capacity()
    }

    fn grow_large_pages(&mut self, free_list: &[Frame]) -> Result<(), AllocationError> {
        for (idx, insert) in free_list.iter().enumerate() {
            match self.release_large_page(*insert) {
                Err(_) => return Err(AllocationError::CantGrowFurther { count: idx }),
                _ => {}
            }
        }
        Ok(())
    }
}

impl ReapBackend for NCache {
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
    /// NCache should be fit in a large-page.
    /// TODO: Ideally this would be an exact fit and the caches would be bigger,
    /// so we need to send a pull request to NCache to allow the sizes we need
    /// once this is more stable.
    #[test]
    fn ncache_is_page_sized() {
        assert!(core::mem::size_of::<NCache>() <= super::LARGE_PAGE_SIZE);
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn ncache_invalid_base_frame_size() {
        let mut ncache = NCache::new(4);
        ncache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1001, 4));
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn ncache_invalid_base_frame_align() {
        let mut ncache = NCache::new(4);
        ncache.release_base_page(Frame::new(PAddr::from(0x2001), 0x1000, 4));
    }

    /// Can't add wrong affinity.
    #[test]
    #[should_panic]
    fn ncache_invalid_affinity() {
        let mut ncache = NCache::new(1);
        ncache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4));
    }

    /// Test the grow interface of the NCache.
    #[test]
    fn ncache_grow_reap() {
        let mut ncache = NCache::new(4);

        // Insert some pages
        let frames = &[
            Frame::new(PAddr::from(0x2000), 0x1000, 4),
            Frame::new(PAddr::from(0x3000), 0x1000, 4),
        ];
        ncache.grow_base_pages(frames);

        let frames = &[
            Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 4),
            Frame::new(PAddr::from(LARGE_PAGE_SIZE * 4), LARGE_PAGE_SIZE, 4),
        ];
        ncache.grow_large_pages(frames);

        let mut free_list = [None];
        ncache.reap_base_pages(&mut free_list);
        assert_eq!(free_list[0].unwrap().base.as_u64(), 0x3000);
        assert_eq!(free_list[0].unwrap().size, 0x1000);
        assert_eq!(free_list[0].unwrap().affinity, 4);

        let mut free_list = [None, None, None];
        ncache.reap_base_pages(&mut free_list);
        assert_eq!(free_list[0].unwrap().base.as_u64(), 0x2000);
        assert_eq!(free_list[0].unwrap().size, 0x1000);
        assert_eq!(free_list[0].unwrap().affinity, 4);
        assert!(free_list[1].is_none());
        assert!(free_list[2].is_none());

        let mut free_list = [None, None];
        ncache.reap_large_pages(&mut free_list);
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
    fn ncache_release_allocate() {
        let mut ncache = NCache::new(2);

        // Insert some pages
        ncache.release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 2));
        ncache.release_base_page(Frame::new(PAddr::from(0x3000), 0x1000, 2));

        ncache.release_large_page(Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 2));
        ncache.release_large_page(Frame::new(
            PAddr::from(LARGE_PAGE_SIZE * 2),
            LARGE_PAGE_SIZE,
            2,
        ));
        assert_eq!(ncache.free(), 2 * BASE_PAGE_SIZE + 2 * LARGE_PAGE_SIZE);

        // Can we allocate
        let f = ncache.allocate_base_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), 0x3000);
        assert_eq!(f.size, 0x1000);
        assert_eq!(f.affinity, 2);

        let f = ncache.allocate_base_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), 0x2000);
        assert_eq!(f.size, 0x1000);
        assert_eq!(f.affinity, 2);

        let f = ncache
            .allocate_base_page()
            .expect_err("Can't allocate more than we gave it");

        assert_eq!(ncache.free(), 2 * LARGE_PAGE_SIZE);

        let f = ncache.allocate_large_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), (LARGE_PAGE_SIZE * 2) as u64);
        assert_eq!(f.size, LARGE_PAGE_SIZE);
        assert_eq!(f.affinity, 2);

        let f = ncache.allocate_large_page().expect("Can allocate");
        assert_eq!(f.base.as_u64(), LARGE_PAGE_SIZE as u64);
        assert_eq!(f.size, LARGE_PAGE_SIZE);
        assert_eq!(f.affinity, 2);

        assert_eq!(ncache.free(), 0);

        let f = ncache
            .allocate_base_page()
            .expect_err("Can't allocate more than we gave it");
    }
}
