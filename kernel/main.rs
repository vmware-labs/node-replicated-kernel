#![feature(no_std)]
#![feature(alloc, collections)]
#![feature(intrinsics, asm, lang_items, const_fn, core, raw, box_syntax)]

#![no_std]

extern crate rlib;
#[macro_use]
pub mod mutex;

//pub mod allocator;

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate collections;

#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate x86;

#[cfg(target_arch="x86_64")]
extern crate slabmalloc;

#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate klogger;

#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate elfloader;

#[cfg(target_arch="x86_64")]
extern crate multiboot;


pub use klogger::*;

mod prelude;
pub mod unwind;

#[cfg(target_arch="x86_64")] #[path="arch/x86_64/mod.rs"]
pub mod arch;

mod mm;
mod scheduler;
mod allocator;


#[cfg(not(test))]
mod std {
    pub use core::fmt;
    pub use core::cmp;
    pub use core::ops;
    pub use core::iter;
    pub use core::option;
    pub use core::marker;
}

/// Kernel entry-point
pub fn kmain()
{
    log!("Reached architecture independent area");

    loop {}

    unreachable!();
}

