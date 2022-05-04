// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use ctor::ctor;
use log::{debug, info};
use node_replication::{Log, Replica};
use x86::current::paging::HUGE_PAGE_SIZE;

use crate::memory::mcache::TCacheSp;
use crate::memory::{GlobalMemory, GrowBackend, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use crate::nr::{KernelNode, Op};
use crate::{main, ExitReason};

pub mod debug;
pub mod exokernel;
pub mod irq;
pub mod kcb;
pub mod memory;
pub mod network;
pub mod process;
pub mod timer;
pub mod vspace;

pub use bootloader_shared::*;

pub const MAX_NUMA_NODES: usize = 12;
pub const MAX_CORES: usize = 192;

pub fn halt() -> ! {
    unsafe { libc::exit(0) };
}

pub fn advance_fs_replica() {
    unimplemented!("eager_advance_fs_replica not implemented for unix");
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);

#[ctor]
fn init_setup() {
    if INITIALIZED.load(Ordering::SeqCst) {
        return;
    } else {
        INITIALIZED.store(true, Ordering::SeqCst);
    }

    // Note anything lower than Info is currently broken
    // because macros in mem management will do a recursive
    // allocation and this stuff is not reentrant...
    let _r = klogger::init("info", 0);

    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // Allocate 32 MiB and add it to our heap
    let mut tc = TCacheSp::new(0);
    let mut mm = memory::MemoryMapper::default();

    // avoids unused code warnings
    let _stack = crate::stack::OwnedStack::new(LARGE_PAGE_SIZE);

    for _i in 0..64 {
        let frame = mm
            .allocate_frame(BASE_PAGE_SIZE)
            .expect("We don't have vRAM available");
        tc.grow_base_pages(&[frame]).expect("Can't add base-page");
    }

    for _i in 0..5 {
        let frame = mm
            .allocate_frame(LARGE_PAGE_SIZE)
            .expect("We don't have vRAM available");
        tc.grow_large_pages(&[frame]).expect("Can't add large-page");
    }

    let frame = mm
        .allocate_frame(2 * HUGE_PAGE_SIZE)
        .expect("We don't have vRAM available");
    let mut annotated_regions = ArrayVec::new();
    annotated_regions.push(frame);
    let global_memory = unsafe { Box::new(GlobalMemory::new(annotated_regions).unwrap()) };
    let global_memory_static: &'static GlobalMemory = Box::leak(global_memory);

    // Construct the Kcb so we can access these things later on in the code
    kcb::get_kcb().set_global_mem(global_memory_static);
    debug!("Memory allocation should work at this point...");

    let log: Arc<Log<Op>> = Arc::try_new(Log::<Op>::new(LARGE_PAGE_SIZE))
        .expect("Not enough memory to initialize system");
    let bsp_replica = Replica::<KernelNode>::new(&log);
    let local_ridx = bsp_replica
        .register()
        .expect("Failed to register with Replica.");
    {
        let kcb = kcb::get_kcb();
        kcb.setup_node_replication(bsp_replica.clone(), local_ridx);
    }
}

#[start]
pub fn start(_argc: isize, _argv: *const *const u8) -> isize {
    init_setup();

    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    main();

    ExitReason::ReturnFromMain as isize
}
