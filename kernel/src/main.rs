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
    alloc_layout_extra
)]
#![no_std]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
extern crate libc;

extern crate rumpkernel;

extern crate driverkit;

extern crate spin;

extern crate rlibc;

extern crate cstr_core;

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
pub mod rumprt;
mod scheduler;
mod time;

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
            debug!("allocated ptr=0x{:x} layout={:?}", ptr as usize, layout);
            ptr
        } else {
            use memory::FMANAGER;
            let f = FMANAGER.allocate(layout);
            let ptr = f.map_or(core::ptr::null_mut(), |region| {
                region.kernel_vaddr().as_mut_ptr()
            });
            /*debug!(
                "allocated big region ptr=0x{:x} layout={:?}",
                ptr as usize, layout
            );*/

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

#[cfg(all(feature = "integration-tests", feature = "test-time"))]
pub fn main() {
    unsafe {
        let tsc = x86::time::rdtsc();
        let tsc2 = x86::time::rdtsc();

        let start = time::Instant::now();
        let done = start.elapsed().as_nanos();
        // We do this twice because I think it traps the first time?
        let start = time::Instant::now();
        let done = start.elapsed().as_nanos();
        sprintln!("rdtsc overhead: {:?} cycles", tsc2 - tsc);
        sprintln!("Instant overhead: {:?} ns", done);

        if cfg!(debug_assertions) {
            assert!(tsc2 - tsc <= 100, "rdtsc overhead big?");
            // TODO: should be less:
            assert!(done <= 100, "Instant overhead big?");
        } else {
            assert!(tsc2 - tsc <= 50);
            // TODO: should be less:
            assert!(done <= 100);
        }
    }
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-rump"))]
pub fn main() {
    extern "C" {
        fn rump_boot_setsigmodel(sig: usize);
        fn rump_init();
    }

    unsafe {
        let start = time::Instant::now();
        rump_boot_setsigmodel(1);
        rump_init();
        sprintln!("rump_init done in {:?}", start.elapsed());
    }
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-buddy"))]
pub fn main() {
    use buddy::FreeBlock;
    use buddy::Heap;
    let mut heap = Heap::new(
        heap_base: *mut u8,
        heap_size: usize,
        free_lists: &mut [*mut FreeBlock],
    );

    let b = heap.allocate(4096, 4096);

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-exit"))]
pub fn main() {
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-pfault"))]
pub fn main() {
    use arch::memory::{paddr_to_kernel_vaddr, PAddr};

    unsafe {
        let paddr = PAddr::from(1024 * 1024 * 1024 * 1);
        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);
        let ptr: *mut u64 = kernel_vaddr.as_mut_ptr();
        let val = *ptr;
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
