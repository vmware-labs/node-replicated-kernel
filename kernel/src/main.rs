#![feature(
    intrinsics,
    asm,
    lang_items,
    const_fn,
    raw,
    box_syntax,
    start,
    panic_implementation,
    panic_info_message,
    alloc,
    allocator_api,
    global_asm,
    linkage,
    duration_as_u128
)]
#![cfg_attr(not(target_os = "none"), feature(libc, extern_crate_item_prelude))]
#![no_std]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
extern crate libc;

extern crate driverkit;

extern crate spin;

extern crate rlibc;

#[macro_use]
extern crate lazy_static;

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

extern crate fringe;

pub use klogger::*;

#[macro_use]
mod prelude;

#[cfg(target_os = "none")]
pub mod panic;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

#[cfg(all(target_arch = "x86_64", target_family = "unix"))]
#[path = "arch/unix/mod.rs"]
pub mod arch;

mod allocator;
mod mm;
mod scheduler;
mod time;

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
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
            let ptr = self.0.lock().allocate(layout);
            debug!("allocated ptr=0x{:x} layout={:?}", ptr as usize, layout);
            ptr
        } else {
            use mm::FMANAGER;
            let f = FMANAGER.allocate_region(layout);
            let ptr = f.map_or(0 as *mut u8, |region| region.kernel_vaddr().as_ptr());
            debug!(
                "allocated big region ptr=0x{:x} layout={:?}",
                ptr as usize, layout
            );

            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
            debug!("dealloc ptr = 0x{:x} layout={:?}", ptr as usize, layout);
            self.0.lock().deallocate(ptr, layout);
        } else {
            debug!(
                "WARN lost big allocation at 0x{:x} layout={:?}",
                ptr as usize, layout
            );
        }
    }
}

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
        use mm::FMANAGER;
        FMANAGER.print_regions();

        let new_region: *mut u8 =
            alloc::alloc::alloc(Layout::from_size_align_unchecked(8192, 4096));
        let p: *mut u8 = new_region.offset(4096);
        assert!(!p.is_null());

        // print current regions
        FMANAGER.print_regions();
    }

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-exit"))]
pub fn main() {
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-pfault"))]
pub fn main() {
    use arch::init_pd;
    use arch::memory::{paddr_to_kernel_vaddr, PAddr};
    use x86::bits64::paging;
    use x86::tlb;

    unsafe {
        let paddr = PAddr::from(4 * 1024 * 1024 * 2);

        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);

        let ptr = kernel_vaddr.as_ptr();

        let val = *ptr;

        debug!("no page fault {}", val);

        init_pd[4] = paging::PDEntry::new(paddr, paging::PDFlags::empty());

        debug!("unmapped page 2");

        tlb::flush_all();

        debug!("flushed TLB");

        //let ptr = 0x8000000 as *mut u8;

        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);

        let ptr = kernel_vaddr.as_ptr();

        let val = *ptr; // page-fault
        assert!(val != 0);
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-gpfault"))]
pub fn main() {
    // Note that int!(13) doesn't work in qemu. It doesn't push an error code properly for it.
    // So we cause a GP by loading garbage in the ss segment register.
    use x86::segmentation::{load_ss, SegmentSelector};
    unsafe {
        load_ss(SegmentSelector::new(99, x86::Ring::Ring3));
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-alloc"))]
pub fn main() {
    use alloc::vec::Vec;
    {
        let mut buf: Vec<u8> = Vec::with_capacity(0);
        for i in 0..1024 {
            buf.push(i as u8);
        }
    } // Make sure we drop here.
    debug!("small allocations work.");

    {
        let size: usize = x86::bits64::paging::BASE_PAGE_SIZE;
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        for i in 0..size {
            buf.push(i as u8);
        }

        let size: usize = x86::bits64::paging::BASE_PAGE_SIZE * 256;
        let mut buf: Vec<usize> = Vec::with_capacity(size);
        for i in 0..size {
            buf.push(i as usize);
        }
    } // Make sure we drop here.
    debug!("large allocations work.");

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-scheduler"))]
pub fn main() {
    debug!("tsc_frequency = {:?}", *time::TSC_FREQUENCY);

    let mut s = scheduler::Scheduler::new();
    unsafe {
        s.spawn(4096, |_yielder| {
            debug!("test from lwt1");
        });
        s.spawn(4096, |_yielder| {
            debug!("test from lwt2");
        });

        s.spawn(4096, |mut yielder| {
            debug!("test from lwt3");
            let _r = yielder.sleep(time::Duration::new(5, 0));
            debug!("lwt3 sleep done");
        });
    }
    s.run();
    s.run();
    s.run();
    s.run();

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-sse"))]
pub fn main() {
    info!("division = {}", 10.0 / 2.19);
    info!("division by zero = {}", 10.0 / 0.0);
    arch::debug::shutdown(ExitReason::Ok);
}
