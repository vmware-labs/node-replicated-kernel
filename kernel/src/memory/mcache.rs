// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MCache is a physical memory manager used to maintain a per-NUMA node memory.
//!
//! It can be a cache but should be big enough to contain all memory on a node.
//!
//! It has the following properties:
//!
//! - Fits in a 2 MiB page
//! - Can allocate and free 2 MiB and 4 KiB Frames very quickly using stacks.
//! - Is not thread-safe, need to wrap it in a Mutex (ideally we have two
//!   interior Mutex for base-page and large-page arrays but that's problematic
//!   because our traits are currently using &mut self).
//! - TODO: Should have a directory-style index to put a list of 2 MiB, 4KiB
//!   pages stack into an entry within the MCache list.
use core::fmt;
use core::mem::MaybeUninit;

use log::{debug, warn};
use static_assertions as sa;

use super::backends::{AllocatorStatistics, GrowBackend, PhysicalPageProvider, ReapBackend};
use super::utils::DataSize;
use super::*;
use crate::arch::memory::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

/// A big cache of base and large pages for a NUMA node, fits on a 2 MiB page.
///
/// Stores 256 GiB of large pages and 512 MiB of base pages.
pub(crate) type FrameCacheLarge = MCache<131071, 131070>;
sa::assert_eq_size!(FrameCacheLarge, [u8; LARGE_PAGE_SIZE]);
sa::const_assert!(core::mem::align_of::<FrameCacheLarge>() <= BASE_PAGE_SIZE);

/// A small cache of 4 KiB and 2 MiB pages, fits on a 4K page.
///
/// Used for example for per-core caches.
pub(crate) type FrameCacheSmall = MCache<381, 128>;
sa::assert_eq_size!(FrameCacheSmall, [u8; BASE_PAGE_SIZE]);
sa::const_assert!(core::mem::align_of::<FrameCacheSmall>() <= BASE_PAGE_SIZE);

/// A slightly bigger cache of 4KiB and less 2MiB pages (than
/// `FrameCacheSmall`), fits on a 2 MiB page.
///
/// Used to allocate early during initialization.
pub(crate) type FrameCacheEarly = MCache<2048, 12>;
sa::const_assert!(core::mem::size_of::<FrameCacheEarly>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheEarly>() <= LARGE_PAGE_SIZE);

/// A simple page-cache for a NUMA node.
///
/// Holds two stacks of pages for O(1) allocation/deallocation.
/// Implements the `GrowBackend` to hand pages out.
pub(crate) struct MCache<const BP: usize, const LP: usize> {
    /// Which node the memory in this cache is from.
    node: atopology::NodeId,
    /// A vector of free, cached base-page addresses
    base_page_addresses: arrayvec::ArrayVec<PAddr, BP>,
    /// A vector of free, cached large-page addresses
    large_page_addresses: arrayvec::ArrayVec<PAddr, LP>,
}

impl<const BP: usize, const LP: usize> super::backends::MemManager for MCache<BP, LP> {}

impl<const BP: usize, const LP: usize> MCache<BP, LP> {
    pub(crate) const fn new(node: atopology::NodeId) -> MCache<BP, LP> {
        MCache {
            node,
            base_page_addresses: arrayvec::ArrayVec::new_const(),
            large_page_addresses: arrayvec::ArrayVec::new_const(),
        }
    }

    pub(crate) fn new_with_frame<const B: usize, const L: usize>(
        node: atopology::NodeId,
        mem: Frame,
    ) -> MCache<B, L> {
        let mut cache = MCache::<B, L>::new(node);
        cache.populate_4k_first(mem);
        cache
    }

    /// Populates a FrameCacheSmall with the memory from `frame`
    ///
    /// This works by repeatedly splitting the `frame`
    /// into smaller pages.
    pub(crate) fn populate_4k_first(&mut self, frame: Frame) {
        let how_many_large_pages = if frame.base_pages() > self.base_page_addresses.capacity() {
            let bytes_left_after_base_full =
                (frame.base_pages() - self.base_page_addresses.capacity()) * BASE_PAGE_SIZE;
            bytes_left_after_base_full / LARGE_PAGE_SIZE
        } else {
            // If this assert fails, we have to rethink what to return here
            debug_assert!(self.base_page_addresses.capacity() * BASE_PAGE_SIZE <= LARGE_PAGE_SIZE);
            1
        };

        self.populate(frame, how_many_large_pages);
    }

    /// Populate the MCache with the given `frame`.
    ///
    /// The Frame can be a multiple of page-size, the policy is
    /// to divide it into ~13% base-pages and 87% large-pages.
    pub(crate) fn populate_2m_first(&mut self, frame: Frame) {
        let how_many_large_pages = (frame.size() / LARGE_PAGE_SIZE) * 87 / 100;
        self.populate(frame, how_many_large_pages)
    }

    fn populate(&mut self, frame: Frame, mut how_many_large_pages: usize) {
        let base_count_before_populate = self.base_page_addresses.len();
        let large_count_before_populate = self.large_page_addresses.len();

        if how_many_large_pages == 0 {
            // Try to have at least one large-page if possible
            how_many_large_pages = 1;
        }
        let (low_frame, mut large_page_aligned_frame) =
            frame.split_at_nearest_large_page_boundary();

        for base_page in low_frame.into_iter() {
            match self.base_page_addresses.try_push(base_page.base) {
                Ok(_x) => continue,
                Err(_e) => break,
            }
        }

        // Add large-pages
        let mut lost_large_pages = 0;
        while how_many_large_pages > 0 && large_page_aligned_frame.size() >= LARGE_PAGE_SIZE {
            let (large_page, rest) = large_page_aligned_frame.split_at(LARGE_PAGE_SIZE);
            match self.large_page_addresses.try_push(large_page.base) {
                Ok(()) => { /* NOP */ }
                Err(_) => {
                    lost_large_pages += 1;
                }
            }

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
                    break;
                }
            }
        }

        if lost_pages > 0 || lost_large_pages > 0 {
            warn!(
                "MCache population lost {} of memory.",
                DataSize::from_bytes(
                    lost_pages * BASE_PAGE_SIZE + lost_large_pages * LARGE_PAGE_SIZE
                )
            );
        }

        debug!(
            "MCache#{} added {} base-pages and {} large-pages.",
            self.node,
            self.base_page_addresses.len() - base_count_before_populate,
            self.large_page_addresses.len() - large_count_before_populate
        );
    }

    /// Initialize an uninitialized MCache and return it.
    pub(crate) fn init(
        ncache: &mut MaybeUninit<MCache<BP, LP>>,
        node: atopology::NodeId,
    ) -> &mut MCache<BP, LP> {
        unsafe {
            (*(ncache.as_mut_ptr())).node = node;
            (*(ncache.as_mut_ptr())).base_page_addresses = arrayvec::ArrayVec::new_const();
            (*(ncache.as_mut_ptr())).large_page_addresses = arrayvec::ArrayVec::new_const();
            ncache.assume_init_mut()
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

impl<const BP: usize, const LP: usize> fmt::Debug for MCache<BP, LP> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MCache {{ free_total: {} (free_4kib: {}), capacity: {}, affinity: {} }}",
            DataSize::from_bytes(self.free()),
            DataSize::from_bytes(self.base_page_addresses.len() * BASE_PAGE_SIZE),
            DataSize::from_bytes(self.capacity()),
            self.node
        )
    }
}

impl<const BP: usize, const LP: usize> AllocatorStatistics for MCache<BP, LP> {
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

impl<const BP: usize, const LP: usize> PhysicalPageProvider for MCache<BP, LP> {
    fn allocate_base_page(&mut self) -> Result<Frame, KError> {
        let paddr = self
            .base_page_addresses
            .pop()
            .ok_or(KError::CacheExhausted)?;
        Ok(self.paddr_to_base_page(paddr))
    }

    fn release_base_page(&mut self, frame: Frame) -> Result<(), KError> {
        assert_eq!(frame.size(), BASE_PAGE_SIZE);
        assert_eq!(frame.base % BASE_PAGE_SIZE, 0);
        assert_eq!(frame.affinity, self.node);

        self.base_page_addresses
            .try_push(frame.base)
            .map_err(|_e| KError::CacheFull)
    }

    fn allocate_large_page(&mut self) -> Result<Frame, KError> {
        let paddr = self
            .large_page_addresses
            .pop()
            .ok_or(KError::CacheExhausted)?;
        Ok(self.paddr_to_large_page(paddr))
    }

    fn release_large_page(&mut self, frame: Frame) -> Result<(), KError> {
        assert_eq!(frame.size(), LARGE_PAGE_SIZE);
        assert_eq!(frame.base % LARGE_PAGE_SIZE, 0);
        assert_eq!(frame.affinity, self.node);

        self.large_page_addresses
            .try_push(frame.base)
            .map_err(|_e| KError::CacheFull)
    }
}

impl<const BP: usize, const LP: usize> GrowBackend for MCache<BP, LP> {
    fn spare_base_page_capacity(&self) -> usize {
        self.base_page_addresses.capacity() - self.base_page_addresses.len()
    }

    fn grow_base_pages(&mut self, free_list: &[Frame]) -> Result<(), KError> {
        for frame in free_list {
            assert_eq!(frame.size(), BASE_PAGE_SIZE);
            assert_eq!(frame.base % BASE_PAGE_SIZE, 0);
            assert_eq!(frame.affinity, self.node);

            self.base_page_addresses
                .try_push(frame.base)
                .map_err(|_e| KError::CacheFull)?;
        }
        Ok(())
    }

    fn spare_large_page_capacity(&self) -> usize {
        self.large_page_addresses.capacity() - self.large_page_addresses.len()
    }

    fn grow_large_pages(&mut self, free_list: &[Frame]) -> Result<(), KError> {
        for frame in free_list {
            assert_eq!(frame.size(), LARGE_PAGE_SIZE);
            assert_eq!(frame.base % LARGE_PAGE_SIZE, 0);
            assert_eq!(frame.affinity, self.node);

            self.large_page_addresses
                .try_push(frame.base)
                .map_err(|_e| KError::CacheFull)?;
        }
        Ok(())
    }
}

impl<const BP: usize, const LP: usize> ReapBackend for MCache<BP, LP> {
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
    extern crate std;

    /// A hack to get an MCache without overflowing our stack in the tests :/
    ///
    /// A stack overflow results when trying allocate this the normal way
    /// (even when using Box / box): https://github.com/rust-lang/rust/issues/53827
    fn get_an_ncache<const BP: usize, const LP: usize>() -> &'static mut MCache<BP, LP> {
        unsafe {
            let layout = Layout::new::<MCache<BP, LP>>();
            let global_alloc = std::alloc::System;
            let ptr = global_alloc.alloc_zeroed(layout);
            core::mem::transmute(ptr as *mut MCache<BP, LP>)
        }
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn ncache_invalid_base_frame_size() {
        let mut ncache = get_an_ncache::<131070, 131070>();
        ncache.node = 4;
        ncache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1001, 4))
            .expect("release");
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn ncache_invalid_base_frame_align() {
        let mut ncache = get_an_ncache::<131070, 131070>();
        ncache.node = 4;
        ncache
            .release_base_page(Frame::new(PAddr::from(0x2001), 0x1000, 4))
            .expect("release");
    }

    /// Can't add wrong affinity.
    #[test]
    #[should_panic]
    fn ncache_invalid_affinity() {
        let mut ncache = get_an_ncache::<131070, 131070>();
        ncache.node = 1;
        ncache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4))
            .expect("release");
    }

    /// Test the grow interface of the MCache.
    #[test]
    fn ncache_grow_reap() {
        let mut ncache = get_an_ncache::<131070, 131070>();
        ncache.node = 4;

        // Insert some pages
        let frames = &[
            Frame::new(PAddr::from(0x2000), 0x1000, 4),
            Frame::new(PAddr::from(0x3000), 0x1000, 4),
        ];
        ncache.grow_base_pages(frames).expect("release");

        let frames = &[
            Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 4),
            Frame::new(PAddr::from(LARGE_PAGE_SIZE * 4), LARGE_PAGE_SIZE, 4),
        ];
        ncache.grow_large_pages(frames).expect("release");

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
        let mut ncache = get_an_ncache::<131070, 131070>();
        ncache.node = 2;

        // Insert some pages
        ncache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 2))
            .expect("release");
        ncache
            .release_base_page(Frame::new(PAddr::from(0x3000), 0x1000, 2))
            .expect("release");

        ncache
            .release_large_page(Frame::new(PAddr::from(LARGE_PAGE_SIZE), LARGE_PAGE_SIZE, 2))
            .expect("release");
        ncache
            .release_large_page(Frame::new(
                PAddr::from(LARGE_PAGE_SIZE * 2),
                LARGE_PAGE_SIZE,
                2,
            ))
            .expect("release");
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

        let _f = ncache
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

        let _f = ncache
            .allocate_base_page()
            .expect_err("Can't allocate more than we gave it");
    }

    /// FrameCacheSmall should be fit exactly within a base-page.
    #[test]
    fn tcache_populate() {
        let tcache: FrameCacheSmall =
            FrameCacheSmall::new_with_frame(4, Frame::new(PAddr::from(0x2000), 10 * 0x1000, 4));
        assert_eq!(tcache.base_page_addresses.len(), 10);
        assert_eq!(tcache.large_page_addresses.len(), 0);

        let tcache: FrameCacheSmall = FrameCacheSmall::new_with_frame(
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
        let mut tcache = FrameCacheSmall::new(4);
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1001, 4))
            .expect("release");
    }

    /// Can't add wrong size.
    #[test]
    #[should_panic]
    fn tcache_invalid_base_frame_align() {
        let mut tcache = FrameCacheSmall::new(4);
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2001), 0x1000, 4))
            .expect("release");
    }

    /// Can't add wrong affinity.
    #[test]
    #[should_panic]
    fn tcache_invalid_affinity() {
        let mut tcache = FrameCacheSmall::new(1);
        tcache
            .release_base_page(Frame::new(PAddr::from(0x2000), 0x1000, 4))
            .expect("release");
    }

    /// Test that reap interface of the FrameCacheSmall.
    #[test]
    fn tcache_reap() {
        let mut tcache = FrameCacheSmall::new(4);

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
        let mut tcache = FrameCacheSmall::new(2);

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
