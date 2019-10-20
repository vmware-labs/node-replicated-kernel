//! A physical memory manager for early system initialization.

use crate::memory::{
    AllocationError, Frame, PAddr, PhysicalAllocator, PhysicalPageProvider, BASE_PAGE_SIZE,
    LARGE_PAGE_SIZE,
};
use crate::round_up;
use core::alloc::{Alloc, AllocErr, Layout};

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

    /// Consumes the allocator and recovers the underlying memory
    /// by returning the remaining Frame.
    pub fn unwrap(self) -> Frame {
        self.region
    }

    unsafe fn allocate_layout(&mut self, layout: Layout) -> Result<Frame, AllocationError> {
        assert!(layout.align() <= BASE_PAGE_SIZE, "Alignment mismatch.");
        let size = round_up!(layout.size(), BASE_PAGE_SIZE);

        if size < self.region.size() {
            // Create a new frame
            let mut region = Frame::new(self.region.base, size, self.region.affinity);

            // Make region of the allocator smaller
            self.region.base = self.region.base + size;
            self.region.size -= size;

            /// Zeroes the Frame
            region.zero();

            debug_assert_eq!(region.base % layout.align(), 0);
            debug_assert_eq!(region.base % BASE_PAGE_SIZE, 0);
            debug_assert!(region.size >= size);

            Ok(region)
        } else {
            Err(AllocationError::OutOfMemory {
                size: layout.size(),
            })
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
        warn!("Allocating LARGE_PAGE_SIZE from an EarlyMemoryAllocator!");
        unsafe {
            let layout = Layout::from_size_align_unchecked(LARGE_PAGE_SIZE, BASE_PAGE_SIZE);
            self.allocate_layout(layout)
        }
    }

    fn release_large_page(&mut self, f: Frame) -> Result<(), AllocationError> {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", f);
    }
}

impl PhysicalAllocator for EarlyPhysicalManager {
    /// Allocate a new physical Frame.
    unsafe fn allocate_frame(&mut self, layout: Layout) -> Result<Frame, AllocationError> {
        self.allocate_layout(layout)
    }

    /// Deallocate a Frame
    unsafe fn deallocate_frame(&mut self, frame: Frame, _layout: Layout) {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", frame);
    }
}
