//! A physical memory manager for early system initialization.

use crate::memory::{AllocationError, Frame, PhysicalPageProvider, BASE_PAGE_SIZE};
use crate::round_up;
use core::alloc::Layout;

/// A very simple allocator that only allocates and doesn't allow
/// deallocations (bump-style allocator).
///
/// It doesn't have to free because the memory allocated from it
/// typically lives forever.
#[derive(Debug)]
pub struct EarlyPhysicalManager {
    pub index: usize,
    region: Frame,
}

impl EarlyPhysicalManager {
    /// Creates a new instance with a given frame.
    pub fn new(region: Frame) -> EarlyPhysicalManager {
        assert!(region.base.as_u64() > 0);
        assert!(region.size % BASE_PAGE_SIZE == 0);

        EarlyPhysicalManager {
            index: 0,
            region: region,
        }
    }

    pub unsafe fn allocate_layout(&mut self, layout: Layout) -> Result<Frame, AllocationError> {
        assert!(layout.align() <= BASE_PAGE_SIZE, "Alignment mismatch.");
        let size = round_up!(layout.size(), BASE_PAGE_SIZE);

        if size <= self.region.size() {
            // Create a new frame
            let (mut low, high) = self.region.split_at(size);
            low.zero();

            self.region = high;

            debug_assert_eq!(low.base % layout.align(), 0);
            debug_assert_eq!(low.base % BASE_PAGE_SIZE, 0);
            debug_assert!(low.size >= layout.size());

            Ok(low)
        } else {
            Err(AllocationError::CacheExhausted)
        }
    }
}

/// A trait to allocate and release physical pages from an allocator.
impl PhysicalPageProvider for EarlyPhysicalManager {
    fn allocate_base_page(&mut self) -> Result<Frame, AllocationError> {
        unsafe {
            let layout = Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE);
            self.allocate_layout(layout)
        }
    }

    fn release_base_page(&mut self, f: Frame) -> Result<(), AllocationError> {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", f);
    }

    fn allocate_large_page(&mut self) -> Result<Frame, AllocationError> {
        unimplemented!("Can't allocate large-pages with this")
    }

    fn release_large_page(&mut self, f: Frame) -> Result<(), AllocationError> {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", f);
    }
}
