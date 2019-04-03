#![feature(
    intrinsics,
    asm,
    lang_items,
    const_fn,
    raw,
    box_syntax,
    start,
    panic_info_message,
    alloc,
    allocator_api,
    global_asm,
    linkage,
    c_variadic,
    alloc_layout_extra,
    ptr_internals,
    compiler_builtins_lib,
    ptr_offset_from
)]
#![no_std]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
extern crate libc;

extern crate rlibc;

#[macro_use]
pub mod mutex;

extern crate alloc;

#[macro_use]
extern crate log;

#[cfg(target_arch = "x86_64")]
extern crate x86;

#[cfg(target_arch = "x86_64")]
extern crate apic;

#[cfg(target_arch = "x86_64")]
extern crate slabmalloc;

#[cfg(target_arch = "x86_64")]
#[macro_use]
extern crate klogger;

#[cfg(target_arch = "x86_64")]
extern crate elfloader;

#[cfg(target_arch = "x86_64")]
extern crate multiboot;

extern crate backtracer;
extern crate rawtime;

#[macro_use]
extern crate lazy_static;

pub use klogger::*;

#[cfg(target_os = "none")]
pub mod panic;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

#[cfg(all(target_arch = "x86_64", target_family = "unix"))]
#[path = "arch/unix/mod.rs"]
pub mod arch;

mod memory;
mod prelude;

#[cfg(target_os = "none")]
pub mod rumprt;

#[cfg(target_os = "none")]
extern crate acpica_sys;

use core::alloc::{GlobalAlloc, Layout};
use memory::{BespinSlabsProvider, PhysicalAllocator};
use slabmalloc::{PageProvider, ZoneAllocator};
use spin::Mutex;

#[allow(dead_code)]
static PAGER: Mutex<BespinSlabsProvider> = Mutex::new(BespinSlabsProvider::new());

#[allow(dead_code)]
pub struct SafeZoneAllocator(Mutex<ZoneAllocator<'static>>);

impl SafeZoneAllocator {
    pub const fn new(provider: &'static Mutex<PageProvider>) -> SafeZoneAllocator {
        SafeZoneAllocator(Mutex::new(ZoneAllocator::new(provider)))
    }
}

unsafe impl GlobalAlloc for SafeZoneAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
            let ptr = self.0.lock().allocate(layout);
            //debug!("allocated ptr=0x{:x} layout={:?}", ptr as usize, layout);
            ptr
        } else {
            use memory::FMANAGER;
            let f = FMANAGER.allocate(layout);
            let ptr = f.map_or(core::ptr::null_mut(), |region| {
                region.kernel_vaddr().as_mut_ptr()
            });

            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        debug!("dealloc ptr = 0x{:x} layout={:?}", ptr as usize, layout);
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
            //debug!("dealloc ptr = 0x{:x} layout={:?}", ptr as usize, layout);
            self.0.lock().deallocate(ptr, layout);
        } else {
            use arch::memory::{kernel_vaddr_to_paddr, VAddr};
            use memory::FMANAGER;
            FMANAGER.deallocate(
                memory::Frame::new(
                    kernel_vaddr_to_paddr(VAddr::from_u64(ptr as u64)),
                    layout.size(),
                ),
                layout,
            );
        }
    }
}

#[allow(dead_code)]
#[cfg_attr(target_os = "none", global_allocator)]
static MEM_PROVIDER: SafeZoneAllocator = SafeZoneAllocator::new(&PAGER);

#[cfg(not(any(test, target_family = "unix")))]
mod std {
    pub use core::cmp;
    pub use core::fmt;
    pub use core::iter;
    pub use core::marker;
    pub use core::ops;
    pub use core::option;
}

#[repr(u8)]
// If this type is modified, update run.sh script as well.
pub enum ExitReason {
    Ok = 0,
    ReturnFromMain = 1,
    KernelPanic = 2,
    OutOfMemory = 3,
    UnhandledInterrupt = 4,
    GeneralProtectionFault = 5,
    PageFault = 6,
}

/// Kernel entry-point
#[cfg(not(feature = "integration-tests"))]
pub fn main() {
    debug!("Reached architecture independent area");
    error!("error");
    warn!("warning");
    info!("info");
    debug!("debug");
    trace!("trace");

    debug!("allocating a region of mem");
    unsafe {
        use memory::FMANAGER;
        FMANAGER.print_info();

        let new_region: *mut u8 =
            alloc::alloc::alloc(Layout::from_size_align_unchecked(8192, 4096));
        let p: *mut u8 = new_region.offset(4096);
        assert!(!p.is_null());

        // print current regions
        FMANAGER.print_info();
    }

    arch::debug::shutdown(ExitReason::Ok);
}

include!("integration_main.rs");
