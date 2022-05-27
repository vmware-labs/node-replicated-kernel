// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use alloc::boxed::Box;
pub use alloc::string::String;
pub use alloc::vec::Vec;
pub use core::prelude::v1::*;

pub(crate) use crate::error::KError;

use core::fmt;
use core::ops::{Deref, DerefMut};

#[macro_export]
macro_rules! round_up {
    ($num:expr, $multiple:expr) => {
        (($num + $multiple - 1) / $multiple) * $multiple
    };
}

#[macro_export]
macro_rules! is_page_aligned {
    ($num:expr) => {
        $num % BASE_PAGE_SIZE as u64 == 0
    };
}

#[macro_export]
macro_rules! is_large_page_aligned {
    ($num:expr) => {
        $num % LARGE_PAGE_SIZE as u64 == 0
    };
}

pub(crate) trait PowersOf2 {
    fn log2(self) -> u8;
}

impl PowersOf2 for usize {
    #[cfg(target_pointer_width = "64")]
    fn log2(self) -> u8 {
        63 - self.leading_zeros() as u8
    }

    #[cfg(target_pointer_width = "32")]
    fn log2(self) -> u8 {
        31 - self.leading_zeros() as u8
    }
}

impl PowersOf2 for u8 {
    fn log2(self) -> u8 {
        7 - self.leading_zeros() as u8
    }
}

/// Pads and aligns a value to the length of a cache line.
///
/// Starting from Intel's Sandy Bridge, spatial prefetcher is now pulling pairs of 64-byte cache
/// lines at a time, so we have to align to 128 bytes rather than 64.
///
/// Sources:
/// - https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf
/// - https://github.com/facebook/folly/blob/1b5288e6eea6df074758f877c849b6e73bbb9fbb/folly/lang/Align.h#L107
///
/// # Origin
/// CachePadded is originally from from crossbeam-utils (https://github.com/crossbeam-rs)
/// Apache/MIT License: with Copyright (c) 2019 The Crossbeam Project Developers
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq)]
#[cfg_attr(target_arch = "x86_64", repr(align(128)))]
#[cfg_attr(not(target_arch = "x86_64"), repr(align(64)))]
pub(crate) struct CachePadded<T> {
    value: T,
}

unsafe impl<T: Send> Send for CachePadded<T> {}
unsafe impl<T: Sync> Sync for CachePadded<T> {}

impl<T> CachePadded<T> {
    /// Pads and aligns a value to the length of a cache line.
    ///
    /// # Examples
    ///
    /// ```
    /// use crossbeam_utils::CachePadded;
    ///
    /// let padded_value = CachePadded::new(1);
    /// ```
    pub(crate) fn new(t: T) -> CachePadded<T> {
        CachePadded::<T> { value: t }
    }
}

impl<T> Deref for CachePadded<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: fmt::Debug> fmt::Debug for CachePadded<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CachePadded")
            .field("value", &self.value)
            .finish()
    }
}

impl<T> From<T> for CachePadded<T> {
    fn from(t: T) -> Self {
        CachePadded::new(t)
    }
}

/// Checks if there is an overlap between two ranges
#[allow(unused)] // Currently only used in integration_main.rs
pub(crate) fn overlaps<T: PartialOrd>(a: &core::ops::Range<T>, b: &core::ops::Range<T>) -> bool {
    a.start < b.end && b.start < a.end
}
