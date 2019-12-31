use log::Level;

use alloc::boxed::Box;

use arrayvec::ArrayVec;

use crate::xmain;
use crate::ExitReason;

use crate::memory::{tcache::TCache, Frame, GlobalMemory, GrowBackend};

pub mod irq;
pub mod kcb;
pub mod memory;
pub mod process;
pub mod vspace;

use crate::kcb::Kcb;
use x86::current::paging::PAddr;

pub use bootloader_shared::*;

pub mod debug {
    use crate::ExitReason;
    pub fn shutdown(val: ExitReason) -> ! {
        unsafe {
            libc::exit(val as i32);
        }
    }
}

#[start]
pub fn start(_argc: isize, _argv: *const *const u8) -> isize {
    // Note anything lower than Info is currently broken
    // because macros in mem management will do a recursive
    // allocation and this stuff is not reentrant...
    let _r = klogger::init("info");

    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // Allocate 32 MiB and add it to our heap
    let mut tc = TCache::new(0, 0);
    let mut mm = memory::MemoryMapper::new();

    for _i in 0..254 {
        let frame = mm
            .allocate_frame(4096)
            .expect("We don't have vRAM available");
        tc.grow_base_pages(&[frame]).expect("Can't add base-page");
    }

    for _i in 0..32 {
        let frame = mm
            .allocate_frame(2 * 1024 * 1024)
            .expect("We don't have vRAM available");
        tc.grow_large_pages(&[frame]).expect("Can't add large-page");
    }

    let frame = mm
        .allocate_frame(16 * 1024 * 1024)
        .expect("We don't have vRAM available");
    let mut annotated_regions = ArrayVec::<[Frame; 64]>::new();
    annotated_regions.push(frame);
    let global_memory = unsafe { GlobalMemory::new(annotated_regions).unwrap() };
    let _global_memory_static =
        unsafe { core::mem::transmute::<&GlobalMemory, &'static GlobalMemory>(&global_memory) };

    // Construct the Kcb so we can access these things later on in the code
    let kernel_args: Box<KernelArgs> = Box::new(Default::default());
    let kernel_binary: &'static [u8] = &[0u8; 1];
    let arch_kcb: kcb::ArchKcb = kcb::ArchKcb::new(Box::leak(kernel_args));

    let kcb = box Kcb::new(&kernel_binary, tc, arch_kcb, 0 as topology::NodeId);

    kcb::init_kcb(Box::leak(kcb));
    debug!("Memory allocation should work at this point...");

    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    #[cfg(not(test))]
    xmain();

    ExitReason::ReturnFromMain as isize
}
