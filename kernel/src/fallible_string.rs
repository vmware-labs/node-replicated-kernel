//! Implement Fallible String
//!
//! Thils file will ideally added to the fallible_collections library.

use alloc::collections::TryReserveError;
use alloc::string::String;

/// trait implementing all fallible methods on vec
pub(crate) trait FallibleString {
    /// see with_capacity
    fn try_with_capacity(capacity: usize) -> Result<String, TryReserveError>;
    /// see push
    fn try_push(&mut self, ch: char) -> Result<(), TryReserveError>;
    /// see push_str
    fn try_push_str(&mut self, string: &str) -> Result<(), TryReserveError>;
}

impl FallibleString for String {
    #[inline]
    fn try_with_capacity(capacity: usize) -> Result<String, TryReserveError> {
        let mut s = String::new();
        s.try_reserve(capacity)?;
        Ok(s)
    }

    #[inline]
    fn try_push(&mut self, ch: char) -> Result<(), TryReserveError> {
        self.try_reserve(1)?;
        self.push(ch);
        Ok(())
    }

    #[inline]
    fn try_push_str(&mut self, string: &str) -> Result<(), TryReserveError> {
        self.try_reserve(string.len())?;
        self.push_str(string);
        Ok(())
    }
}

/// TryString is a thin wrapper around String to provide support for fallible
/// allocation.
///
/// See the crate documentation for more.
#[derive(PartialEq)]
pub(crate) struct TryString {
    inner: String,
}

impl From<TryString> for String {
    fn from(s: TryString) -> String {
        s.inner
    }
}

impl core::convert::TryFrom<&str> for TryString {
    type Error = TryReserveError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut inner = String::new();
        inner.try_reserve(value.len())?;
        inner.push_str(value);
        Ok(TryString { inner })
    }
}
