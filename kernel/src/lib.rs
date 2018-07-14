#![deny(warnings)]
#![feature(
    intrinsics,
    asm,
    lang_items,
    const_fn,
    core,
    raw,
    box_syntax,
    start,
    panic_implementation,
    alloc,
    allocator_api,
    heap_api,
    global_asm
)]
#![no_std]

extern crate spin;

extern crate rlibc;
#[macro_use]
pub mod mutex;

extern crate alloc;

#[cfg(target_arch = "x86_64")]
extern crate x86;

#[cfg(target_arch = "x86_64")]
extern crate slabmalloc;

#[cfg(target_arch = "x86_64")]
#[macro_use]
extern crate klogger;

#[cfg(target_arch = "x86_64")]
extern crate elfloader;

#[cfg(target_arch = "x86_64")]
extern crate multiboot;

pub use klogger::*;

#[macro_use]
mod prelude;
pub mod unwind;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

mod allocator;
mod mm;

use core::alloc::{GlobalAlloc, Layout};
use mm::BespinSlabsProvider;
use slabmalloc::{PageProvider, ZoneAllocator};
use spin::Mutex;

unsafe impl Send for BespinSlabsProvider {}
unsafe impl Sync for BespinSlabsProvider {}

static PAGER: Mutex<BespinSlabsProvider> = Mutex::new(BespinSlabsProvider::new());

pub struct SafeZoneAllocator(Mutex<ZoneAllocator<'static>>);

impl SafeZoneAllocator {
    pub const fn new(provider: &'static Mutex<PageProvider>) -> SafeZoneAllocator {
        SafeZoneAllocator(Mutex::new(ZoneAllocator::new(provider)))
    }
}

unsafe impl GlobalAlloc for SafeZoneAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        slog!("alloc {:?}", layout);
        assert!(layout.align().is_power_of_two());
        self.0.lock().allocate(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().deallocate(ptr, layout);
    }
}

#[global_allocator]
static MEM_PROVIDER: SafeZoneAllocator = SafeZoneAllocator::new(&PAGER);

#[cfg(not(test))]
mod std {
    pub use core::cmp;
    pub use core::fmt;
    pub use core::iter;
    pub use core::marker;
    pub use core::ops;
    pub use core::option;
}

/// Kernel entry-point
pub fn main() {
    slog!("Reached architecture independent area");

    loop {}
}

pub fn oom() {
    slog!("oom");
    loop {}
}
