//! vibrio is the user-space library that interacts with the kernel.
//!
//! It also incorporates and exports the [kpi] crate defines the interface between
//! the kernel and user-space (clients should only have to rely on this crate).
#![no_std]
#![feature(
    alloc_error_handler,
    const_fn,
    panic_info_message,
    c_variadic,
    ptr_internals,
    asm
)]

extern crate alloc;
extern crate kpi;

#[cfg(feature = "rumprt")]
#[macro_use]
extern crate lazy_static;

pub mod syscalls;

pub mod mem;
pub mod writer;

pub mod upcalls;

#[cfg(feature = "rumprt")]
pub mod rumprt;

//pub use syscalls::{exit, print, vspace};
