//! vibrio is the user-space library that interacts with the kernel.
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

#[macro_use]
extern crate lazy_static;

mod syscalls;

pub use kpi::*;

pub mod mem;
pub mod writer;

pub mod rumprt;

use kpi::*;
pub use syscalls::*;
