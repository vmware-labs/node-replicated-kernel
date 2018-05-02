#![feature(intrinsics, asm, lang_items, const_fn, core, raw, box_syntax, start)]
#![feature(alloc, global_allocator, allocator_api, heap_api)]
#![feature(global_asm)]
#![no_std]
#![no_main]

extern crate spin;

extern crate rlibc;
#[macro_use]
pub mod mutex;

extern crate alloc;

#[cfg(target_arch="x86_64")]
extern crate x86;

#[cfg(target_arch="x86_64")]
extern crate slabmalloc;

#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate klogger;

#[cfg(target_arch="x86_64")]
extern crate elfloader;

#[cfg(target_arch="x86_64")]
extern crate multiboot;


pub use klogger::*;

#[macro_use]
mod prelude;
pub mod unwind;

#[cfg(target_arch="x86_64")] #[path="arch/x86_64/mod.rs"]
pub mod arch;

mod mm;
mod scheduler;
mod allocator;

use slabmalloc::{SafeZoneAllocator};
use spin::Mutex;
use mm::{BespinSlabsProvider};

unsafe impl Send for BespinSlabsProvider { }
unsafe impl Sync for BespinSlabsProvider { }

static PAGER: Mutex<BespinSlabsProvider> = Mutex::new(BespinSlabsProvider::new());
#[global_allocator]
static MEM_PROVIDER: SafeZoneAllocator = SafeZoneAllocator::new(&PAGER);


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
pub fn main()
{
    slog!("Reached architecture independent area");

    loop {}
}

pub fn oom() {
	slog!("oom");
	loop{}
}