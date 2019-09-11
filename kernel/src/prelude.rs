use core::ops::{Deref, DerefMut};

#[macro_export]
macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

#[macro_export]
macro_rules! is_page_aligned {
    ($num:expr) => {
        $num % BASE_PAGE_SIZE as u64 == 0
    };
}

pub trait PowersOf2 {
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

#[allow(unions_with_drop_fields)]
#[derive(Copy)]
union UnionFlag<T> {
    value: T,
}

impl<T: Clone> Clone for UnionFlag<T> {
    fn clone(&self) -> Self {
        unsafe {
            UnionFlag {
                value: self.value.clone(),
            }
        }
    }
}

/// A type holding **T** that will not call its destructor on drop
///
/// The untagged unions implementation of `NoDrop<T>` is Copy where T: Copy,
/// which was not possible in the stable implementation.
#[derive(Copy, Clone)]
pub struct NoDrop<T>(UnionFlag<T>);

impl<T> NoDrop<T> {
    /// Create a new **NoDrop**.
    #[inline]
    pub fn new(value: T) -> Self {
        NoDrop(UnionFlag { value: value })
    }

    /// Extract the inner value.
    ///
    /// Once extracted, the value can of course drop again.
    #[inline]
    pub fn into_inner(self) -> T {
        unsafe { self.0.value }
    }
}

impl<T> Deref for NoDrop<T> {
    type Target = T;

    // Use type invariant, always initialized
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &self.0.value }
    }
}

impl<T> DerefMut for NoDrop<T> {
    // Use type invariant, always initialized
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut self.0.value }
    }
}
