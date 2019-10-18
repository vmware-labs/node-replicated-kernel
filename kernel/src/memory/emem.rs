//! A physical memory manager for early system initialization.

use crate::memory::{Frame, PAddr, PhysicalAllocator, BASE_PAGE_SIZE};
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
}

impl PhysicalAllocator for EarlyPhysicalManager {
    /// Allocate a new physical Frame.
    unsafe fn allocate_frame(&mut self, layout: Layout) -> Result<Frame, &'static str> {
        assert!(layout.align() <= BASE_PAGE_SIZE, "Too much alignment.");
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
            Err("Can't support requested allocation size.")
        }
    }

    /// Deallocate a Frame
    unsafe fn deallocate_frame(&mut self, frame: Frame, _layout: Layout) {
        unreachable!("EarlyPhysicalAllocator can't deallocate {:?}", frame);
    }
}
