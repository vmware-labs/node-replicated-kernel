// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Utility code for dealing with memory / bytes etc.

use core::fmt;

use super::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

/// Calculate how many base and large pages we need to fit a given size.
///
/// # Returns
/// - A tuple containing (base-pages, large-pages).
/// - base-pages will never exceed LARGE_PAGE_SIZE / BASE_PAGE_SIZE.
pub(crate) fn size_to_pages(size: usize) -> (usize, usize) {
    let bytes_not_in_large = size % LARGE_PAGE_SIZE;

    let div = bytes_not_in_large / BASE_PAGE_SIZE;
    let rem = bytes_not_in_large % BASE_PAGE_SIZE;
    let base_pages = if rem > 0 { div + 1 } else { div };

    let remaining_size = size - bytes_not_in_large;
    let div = remaining_size / LARGE_PAGE_SIZE;
    let rem = remaining_size % LARGE_PAGE_SIZE;
    let large_pages = if rem > 0 { div + 1 } else { div };

    (base_pages, large_pages)
}

/// Human-readable representation of a data-size.
///
/// # Notes
/// Use for pretty printing and debugging only.
#[derive(PartialEq)]
pub(crate) enum DataSize {
    Bytes(f64),
    KiB(f64),
    MiB(f64),
    GiB(f64),
}

impl DataSize {
    /// Construct a new DataSize passing the amount of `bytes`
    /// we want to convert
    pub(crate) fn from_bytes(bytes: usize) -> DataSize {
        if bytes < 1024 {
            DataSize::Bytes(bytes as f64)
        } else if bytes < (1024 * 1024) {
            DataSize::KiB(bytes as f64 / 1024.0)
        } else if bytes < (1024 * 1024 * 1024) {
            DataSize::MiB(bytes as f64 / (1024 * 1024) as f64)
        } else {
            DataSize::GiB(bytes as f64 / (1024 * 1024 * 1024) as f64)
        }
    }

    /// Write rounded size and SI unit to `f`
    fn format(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DataSize::Bytes(n) => write!(f, "{:.2} B", n),
            DataSize::KiB(n) => write!(f, "{:.2} KiB", n),
            DataSize::MiB(n) => write!(f, "{:.2} MiB", n),
            DataSize::GiB(n) => write!(f, "{:.2} GiB", n),
        }
    }
}

impl fmt::Debug for DataSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format(f)
    }
}

impl fmt::Display for DataSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

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
