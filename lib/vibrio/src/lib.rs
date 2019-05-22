//! vibrio is the user-space library that interacts with the kernel.
#![no_std]
#![feature(alloc_error_handler, const_fn, panic_info_message)]

extern crate alloc;
extern crate kpi;

mod syscalls;

pub use kpi::*;
pub use syscalls::*;
pub mod mem;
pub mod writer;
