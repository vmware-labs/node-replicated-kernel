// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Frames -- physical regions of memory.

use core::fmt;
use core::iter;

use crate::arch::memory::{paddr_to_kernel_vaddr, PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use crate::round_up;

use super::utils::DataSize;

/// Physical region of memory.
///
/// A frame is always aligned to a page-size.
/// A frame's size is a multiple of `BASE_PAGE_SIZE`.
///
/// # Note on naming
/// Historically frames refer to physical (base)-pages in OS terminology.
/// In our case a frame can be a multiple of a page -- it may be more fitting
/// to call it a memory-block.
#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) struct Frame {
    pub base: PAddr,
    pub size: usize,
    pub affinity: atopology::NodeId,
}

impl Frame {
    /// Create a new Frame given a PAddr range (from, to)
    pub(crate) fn from_range(range: (PAddr, PAddr), node: atopology::NodeId) -> Frame {
        assert_eq!(range.0 % BASE_PAGE_SIZE, 0);
        assert_eq!(range.1 % BASE_PAGE_SIZE, 0);
        assert!(range.0 < range.1);

        Frame {
            base: range.0,
            size: (range.1 - range.0).into(),
            affinity: node,
        }
    }

    /// Make a new Frame at `base` with `size` with affinity `node`.
    pub(crate) fn new(base: PAddr, size: usize, node: atopology::NodeId) -> Frame {
        assert_eq!(base % BASE_PAGE_SIZE, 0);
        assert_eq!(size % BASE_PAGE_SIZE, 0);

        Frame {
            base,
            size,
            affinity: node,
        }
    }

    /// Construct an empty, zero-length Frame.
    pub(crate) const fn empty() -> Frame {
        Frame {
            base: PAddr::zero(),
            size: 0,
            affinity: 0,
        }
    }

    /// Represent the Frame as a mutable slice of `T`.
    ///
    /// TODO: Bug (should we panic if we don't fit
    /// T's exactly?)
    unsafe fn as_mut_slice<T>(&mut self) -> Option<&mut [T]> {
        if self.size % core::mem::size_of::<T>() == 0 {
            Some(core::slice::from_raw_parts_mut(
                self.kernel_vaddr().as_mut_ptr::<T>(),
                self.size / core::mem::size_of::<T>(),
            ))
        } else {
            None
        }
    }

    /// Splits a given Frame into two (`low`, `high`).
    ///
    /// - `high` will be aligned to LARGE_PAGE_SIZE or Frame::empty() if
    ///    the frame can not be aligned to a large-page within its size.
    /// - `low` will be everything below alignment or Frame::empty() if `self`
    ///    is already aligned to `LARGE_PAGE_SIZE`
    pub(crate) fn split_at_nearest_large_page_boundary(self) -> (Frame, Frame) {
        if self.base % LARGE_PAGE_SIZE == 0 {
            (Frame::empty(), self)
        } else {
            let new_high_base = PAddr::from(round_up!(self.base.as_usize(), LARGE_PAGE_SIZE));
            let split_at = new_high_base - self.base;

            self.split_at(split_at.as_usize())
        }
    }

    /// Splits a given Frame into two, returns both as
    /// a (`low`, `high`) tuple.
    ///
    /// If `size` is bigger than `self`, `high`
    /// will be an `empty` frame.
    ///
    /// # Panics
    /// Panics if size is not a multiple of base page-size.
    pub(crate) fn split_at(self, size: usize) -> (Frame, Frame) {
        assert_eq!(size % BASE_PAGE_SIZE, 0);

        if size >= self.size() {
            (self, Frame::empty())
        } else {
            let low = Frame::new(self.base, size, self.affinity);
            let high = Frame::new(self.base + size, self.size() - size, self.affinity);

            (low, high)
        }
    }

    /// Represent the Frame as a slice of `T`.
    ///
    /// TODO: Bug (should we panic if we don't fit
    /// T's exactly?)
    #[allow(unused)]
    unsafe fn as_slice<T>(&self) -> Option<&[T]> {
        if self.size % core::mem::size_of::<T>() == 0 {
            Some(core::slice::from_raw_parts(
                self.kernel_vaddr().as_mut_ptr::<T>(),
                self.size / core::mem::size_of::<T>(),
            ))
        } else {
            None
        }
    }

    /// Represent the Frame as MaybeUinit<T>
    pub unsafe fn uninitialized<T>(self) -> &'static mut core::mem::MaybeUninit<T> {
        debug_assert!(core::mem::size_of::<T>() <= self.size);
        core::mem::transmute::<u64, &'static mut core::mem::MaybeUninit<T>>(
            self.kernel_vaddr().into(),
        )
    }

    /// Fill the page with many `T`'s.
    ///
    /// TODO: Think about this, should maybe return uninitialized
    /// instead?
    unsafe fn fill<T: Copy>(&mut self, pattern: T) -> bool {
        self.as_mut_slice::<T>().map_or(false, |obj| {
            for e in obj {
                *e = pattern;
            }
            true
        })
    }

    /// Size of the region (in 4K pages).
    pub(crate) fn base_pages(&self) -> usize {
        self.size / BASE_PAGE_SIZE
    }

    #[cfg(test)]
    pub(crate) fn is_large_page_aligned(&self) -> bool {
        self.base % LARGE_PAGE_SIZE == 0
    }

    /// Size of the region (in bytes).
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    pub(crate) fn end(&self) -> PAddr {
        self.base + self.size
    }

    /// Zero the frame using `memset`.
    pub unsafe fn zero(&mut self) {
        self.fill(0);
    }

    /// The kernel virtual address for this region.
    pub(crate) fn kernel_vaddr(&self) -> VAddr {
        paddr_to_kernel_vaddr(self.base)
    }
}

pub(crate) struct IntoBasePageIter {
    frame: Frame,
}

impl iter::ExactSizeIterator for IntoBasePageIter {
    fn len(&self) -> usize {
        self.frame.size() / BASE_PAGE_SIZE
    }
}

impl iter::FusedIterator for IntoBasePageIter {}

impl iter::Iterator for IntoBasePageIter {
    // we will be counting with usize
    type Item = Frame;

    fn next(&mut self) -> Option<Self::Item> {
        use core::cmp::Ordering;
        match self.frame.size().cmp(&BASE_PAGE_SIZE) {
            Ordering::Greater => {
                let (low, high) = self.frame.split_at(BASE_PAGE_SIZE);
                self.frame = high;
                Some(low)
            }
            Ordering::Equal => {
                let mut last_page = Frame::empty();
                core::mem::swap(&mut last_page, &mut self.frame);
                Some(last_page)
            }
            Ordering::Less => None,
        }
    }
}

impl iter::IntoIterator for Frame {
    type Item = Frame;
    type IntoIter = IntoBasePageIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoBasePageIter { frame: self }
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Frame {{ 0x{:x} -- 0x{:x} (size = {}, pages = {}, node#{} }}",
            self.base,
            self.base + self.size,
            DataSize::from_bytes(self.size),
            self.base_pages(),
            self.affinity
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_iter() {
        let frame = Frame::new(PAddr::from(8 * 1024 * 1024), 4096 * 3, 0);
        let mut iter = frame.into_iter();
        assert_eq!(iter.len(), 3);

        let f1 = iter.next().unwrap();
        assert_eq!(f1.base, PAddr::from(8 * 1024 * 1024));
        assert_eq!(f1.size(), BASE_PAGE_SIZE);

        let f2 = iter.next().unwrap();
        assert_eq!(f2.base, PAddr::from(8 * 1024 * 1024 + 4096));
        assert_eq!(f2.size(), BASE_PAGE_SIZE);

        let f3 = iter.next().unwrap();
        assert_eq!(f3.base, PAddr::from(8 * 1024 * 1024 + 4096 + 4096));
        assert_eq!(f3.size(), BASE_PAGE_SIZE);

        let f4 = iter.next();
        assert_eq!(f4, None);

        let f4 = iter.next();
        assert_eq!(f4, None);

        assert_eq!(Frame::empty().into_iter().next(), None);
    }

    #[test]
    fn frame_split_at_nearest_large_page_boundary() {
        let f = Frame::new(PAddr::from(8 * 1024 * 1024), 4096 * 10, 0);
        assert_eq!(
            f.split_at_nearest_large_page_boundary(),
            (Frame::empty(), f)
        );

        let f = Frame::new(PAddr::from(LARGE_PAGE_SIZE - 5 * 4096), 4096 * 10, 0);
        let low = Frame::new(PAddr::from(LARGE_PAGE_SIZE - 5 * 4096), 4096 * 5, 0);
        let high = Frame::new(PAddr::from(LARGE_PAGE_SIZE), 4096 * 5, 0);
        assert_eq!(f.split_at_nearest_large_page_boundary(), (low, high));

        let f = Frame::new(PAddr::from(BASE_PAGE_SIZE), 4096 * 5, 0);
        assert_eq!(
            f.split_at_nearest_large_page_boundary(),
            (f, Frame::empty())
        );
    }

    #[test]
    fn frame_large_page_aligned() {
        let f = Frame::new(PAddr::from(0xf000), 4096 * 10, 0);
        assert!(!f.is_large_page_aligned());

        let f = Frame::new(PAddr::from(8 * 1024 * 1024), 4096 * 10, 0);
        assert!(f.is_large_page_aligned());
    }

    #[test]
    fn frame_split_at() {
        let f = Frame::new(PAddr::from(0xf000), 4096 * 10, 0);
        let (low, high) = f.split_at(4 * 4096);

        assert_eq!(low.base.as_u64(), 0xf000);
        assert_eq!(low.size(), 4 * 4096);
        assert_eq!(high.base.as_u64(), 0xf000 + 4 * 4096);
        assert_eq!(high.size(), 6 * 4096);
    }

    #[test]
    fn frame_base_pages() {
        let f = Frame::new(PAddr::from(0x1000), 4096 * 10, 0);
        assert_eq!(f.base_pages(), 10);
    }

    #[test]
    fn frame_size() {
        let f = Frame::new(PAddr::from(0xf000), 4096 * 10, 0);
        assert_eq!(f.size(), f.size);
        assert_eq!(f.size(), 4096 * 10);
    }

    #[test]
    fn frame_end() {
        let f = Frame::new(PAddr::from(0x1000), 4096 * 10, 0);
        assert_eq!(f.end(), PAddr::from(4096 * 10 + 0x1000));
    }

    #[test]
    #[should_panic]
    /// Frames should be aligned to BASE_PAGE_SIZE.
    fn frame_bad_alignment() {
        let _f = Frame::new(PAddr::from(usize::MAX), BASE_PAGE_SIZE, 0);
    }

    #[test]
    #[should_panic]
    /// Frames size should be multiple of BASE_PAGE_SIZE.
    fn frame_bad_size() {
        let _f = Frame::new(PAddr::from(0x1000), 0x13, 0);
    }

    #[test]
    fn size_formatting() {
        let ds = DataSize::from_bytes(LARGE_PAGE_SIZE);
        assert_eq!(ds, DataSize::MiB(2.0));

        let ds = DataSize::from_bytes(BASE_PAGE_SIZE);
        assert_eq!(ds, DataSize::KiB(4.0));

        let ds = DataSize::from_bytes(1024 * LARGE_PAGE_SIZE);
        assert_eq!(ds, DataSize::GiB(2.0));

        let ds = DataSize::from_bytes(usize::MIN);
        assert_eq!(ds, DataSize::Bytes(0.0));
    }
}
