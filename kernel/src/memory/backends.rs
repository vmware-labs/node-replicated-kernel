// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Interface definitions for communication backends to transport free memory
//! between different allocators and query allocator info.

use crate::error::KResult;

use super::frame::Frame;

/// Composite of trait that needs to be implemented by anything that wants to
/// manage memory.
pub(crate) trait MemManager:
    PhysicalPageProvider + AllocatorStatistics + GrowBackend
{
}

/// A trait to allocate and release physical pages from an allocator.
pub(crate) trait PhysicalPageProvider {
    /// Allocate a `BASE_PAGE_SIZE` for the given architecture from the allocator.
    fn allocate_base_page(&mut self) -> KResult<Frame>;
    /// Release a `BASE_PAGE_SIZE` for the given architecture back to the allocator.
    fn release_base_page(&mut self, f: Frame) -> KResult<()>;

    /// Allocate a `LARGE_PAGE_SIZE` for the given architecture from the allocator.
    fn allocate_large_page(&mut self) -> KResult<Frame>;
    /// Release a `LARGE_PAGE_SIZE` for the given architecture back to the allocator.
    fn release_large_page(&mut self, f: Frame) -> KResult<()>;
}

/// The backend implementation necessary to implement if we want a client to be
/// able to grow our allocator by providing a list of frames.
pub(crate) trait GrowBackend {
    /// How much capacity we have left to add base pages.
    fn spare_base_page_capacity(&self) -> usize;

    /// Add a slice of base-pages to `self`.
    fn grow_base_pages(&mut self, free_list: &[Frame]) -> KResult<()>;

    /// How much capacity we have left to add large pages.
    fn spare_large_page_capacity(&self) -> usize;

    /// Add a slice of large-pages to `self`.
    fn grow_large_pages(&mut self, free_list: &[Frame]) -> KResult<()>;
}

/// The backend implementation necessary to implement if we want
/// a system manager to take away be able to take away memory
/// from our allocator.
pub(crate) trait ReapBackend {
    /// Ask to give base-pages back.
    ///
    /// An implementation should put the pages in the `free_list` and remove
    /// them from the local allocator.
    fn reap_base_pages(&mut self, free_list: &mut [Option<Frame>]);

    /// Ask to give large-pages back.
    ///
    /// An implementation should put the pages in the `free_list` and remove
    /// them from the local allocator.
    fn reap_large_pages(&mut self, free_list: &mut [Option<Frame>]);
}

/// Provides information about an allocator.
pub(crate) trait AllocatorStatistics {
    /// Current free memory (in bytes) this allocator has.
    fn free(&self) -> usize {
        self.size() - self.allocated()
    }

    /// Memory (in bytes) that was handed out by this allocator
    /// and has not yet been reclaimed (memory currently in use).
    fn allocated(&self) -> usize;

    /// Total memory (in bytes) that is maintained by this allocator.
    fn size(&self) -> usize;

    /// Potential capacity (in bytes) that the allocator can maintain.
    ///
    /// Some allocator may have unlimited capacity, in that case
    /// they can return usize::max.
    ///
    /// e.g. this should hold `capacity() >= free() + allocated()`
    fn capacity(&self) -> usize;

    /// Internal fragmentation produced by this allocator (in bytes).
    ///
    /// In some cases an allocator may not be able to calculate it.
    fn internal_fragmentation(&self) -> usize;

    fn free_base_pages(&self) -> usize {
        0
    }

    fn free_large_pages(&self) -> usize {
        0
    }
}
