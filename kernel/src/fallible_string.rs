//! Implement Fallible String
//!
//! Thils file will ideally added to the fallible_collections library.

use alloc::collections::TryReserveError;
use alloc::string::String;

/// trait implementing all fallible methods on vec
pub trait FallibleString {
    /// see push
    fn try_push(&mut self, ch: char) -> Result<(), TryReserveError>;
    /// see push_str
    fn try_push_str(&mut self, string: &str) -> Result<(), TryReserveError>;
}

impl FallibleString for String {
    #[inline]
    fn try_push(&mut self, ch: char) -> Result<(), TryReserveError> {
        self.try_reserve(1)?;
        Ok(self.push(ch))
    }

    #[inline]
    fn try_push_str(&mut self, string: &str) -> Result<(), TryReserveError> {
        self.try_reserve(string.len())?;
        Ok(self.push_str(string))
    }
}

/// TryString is a thin wrapper around String to provide support for fallible
/// allocation.
///
/// See the crate documentation for more.
#[derive(PartialEq)]
pub struct TryString {
    inner: String,
}

impl Into<String> for TryString {
    fn into(self) -> String {
        self.inner
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
