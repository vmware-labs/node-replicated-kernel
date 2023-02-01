// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use cnr::Replica as MlnrReplica;
use ctor::ctor;
use fallible_collections::TryClone;
use log::{debug, info};
use node_replication::{Log, Replica};
use x86::current::paging::HUGE_PAGE_SIZE;

use crate::fs::cnrfs::MlnrKernelNode;
use crate::memory::backends::GrowBackend;
use crate::memory::global::GlobalMemory;
use crate::memory::mcache::FrameCacheEarly;
use crate::memory::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use crate::nr::{KernelNode, Op};
use crate::{main, ExitReason};

pub mod coreboot;
pub mod debug;
pub mod irq;
pub mod kcb;
pub mod memory;
#[cfg(feature = "rackscale")]
pub mod network;
pub mod process;
#[cfg(feature = "rackscale")]
pub mod rackscale;
pub mod signals;
pub mod syscalls;
pub mod timer;
pub mod tlb;
pub mod vspace;

pub use bootloader_shared::*;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;
pub(crate) const MAX_MACHINES: usize = u8::MAX as usize;

pub(crate) fn halt() -> ! {
    unsafe { libc::exit(0) };
}

pub(crate) fn advance_fs_replica() {
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
    let mut tc = FrameCacheEarly::new(0);
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
    unsafe { kcb::PER_CORE_MEMORY.set_global_mem(global_memory_static) };
    debug!("Memory allocation should work at this point...");

    let log: Arc<Log<Op>> = Arc::try_new(Log::<Op>::new(LARGE_PAGE_SIZE))
        .expect("Not enough memory to initialize system");
    let bsp_replica = Replica::<KernelNode>::new(&log);
    let local_ridx = bsp_replica
        .register()
        .expect("Failed to register with Replica.");
    crate::nr::NR_REPLICA.call_once(|| (bsp_replica.clone(), local_ridx));

    // Starting to initialize file-system
    let fs_logs = crate::fs::cnrfs::allocate_logs();
    // Construct the first replica
    let fs_replica = MlnrReplica::<MlnrKernelNode>::new(
        fs_logs
            .try_clone()
            .expect("Not enough memory to initialize system"),
    );
    crate::fs::cnrfs::init_cnrfs_on_thread(fs_replica.clone());

    // Initialize processes
    lazy_static::initialize(&process::PROCESS_TABLE);
    crate::nrproc::register_thread_with_process_replicas();
}

#[start]
pub(crate) fn start(_argc: isize, _argv: *const *const u8) -> isize {
    init_setup();

    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    main();

    ExitReason::ReturnFromMain as isize
}
