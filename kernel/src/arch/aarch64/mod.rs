// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! AArch64 specific kernel code.

use alloc::sync::Arc;
use core::arch::asm;
use core::arch::global_asm;
use core::mem::transmute;

use cortex_a::{asm::barrier, registers::*};
use fallible_collections::TryClone;
use tock_registers::interfaces::{Readable, Writeable};

use cnr::Replica as MlnrReplica;
use node_replication::{Log, Replica};

use crate::fs::cnrfs::MlnrKernelNode;
use crate::memory::global::GlobalMemory;
use crate::memory::LARGE_PAGE_SIZE;
use crate::nr::{KernelNode, Op};

use crate::arch::memory::identify_numa_affinity;

use crate::cmdline::CommandLineArguments;
use crate::memory::per_core::PerCoreMemory;

pub use bootloader_shared::*;
use klogger::sprint;

//pub mod acpi;
pub mod coreboot;
pub mod debug;
mod exceptions;
pub mod kcb;
pub mod memory;
pub mod process;
pub mod signals;
mod syscall;
pub mod timer;
pub mod vspace;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;

// // Include the `jump_to_kernel` assembly function. This does some things we can't express in
// // rust like switching the stack.
// global_asm!(include_str!("exceptions.S"));

extern "C" {
    static __exn_vectors_start: u32;
    static __exn_vectors_end: u32;
}

/// Goes to sleep / halts the core.
///
/// Interrupts are enabled before going to sleep.
pub(crate) fn halt() -> ! {
    unsafe {
        loop {
            asm!("wfi")
        }
    }
}

/// For cores that advances the replica eagerly. This avoids additional IPI costs.
pub(crate) fn advance_fs_replica() {
    panic!("not yet implemented");
}

use core::ptr::{read_volatile, write_volatile};

/// Entry function that is called from UEFI At this point we are in x86-64
/// (long) mode, We have a simple GDT, our address space, and stack set-up. The
/// argc argument is abused as a pointer ot the KernelArgs struct passed by
/// UEFI.
#[cfg(target_os = "none")]
#[start]
#[no_mangle]
fn _start(argc: isize, _argv: *const *const u8) -> isize {
    // probably should make the address a cmdline argument at some point...
    klogger::init(
        crate::CMDLINE.get().map(|c| c.log_filter).unwrap_or("info"),
        0xffff_0000_0900_0000,
    )
    .expect("Can't set-up logging");

    let el = CurrentEL.read(CurrentEL::EL);
    log::info!("Starting kernel on aarch64 in EL{:?}", el);
    log::info!("Kernel starting at {:p}", &_start as *const _);

    // set up exception vectors with the assembly code
    unsafe {
        log::info!("Setting up exception vectors: {:p}", &__exn_vectors_start);
        let exn_vector_size =
            (&__exn_vectors_end as *const _ as u64) - (&__exn_vectors_start as *const _ as u64);
        if exn_vector_size != 2048 {
            panic!(
                "Exception vector size is not 2048 bytes (was: {})",
                exn_vector_size
            );
        }
        VBAR_EL1.set(&__exn_vectors_start as *const _ as u64);
        barrier::isb(barrier::SY);
    }

    // Make sure these constants are initialized early, for proper time
    // accounting (otherwise because they are lazy_static we may not end up
    // using them until way later).
    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // We construct a &'static for KernelArgs
    let kernel_args: &'static KernelArgs =
        // Safety:
        // - argc is of correct size and alignment: Yes, was allocated by
        //   bootloader
        // - argc is properly initialized: Yes, contract with bootloader
        // - argc is valid for &'static lifetime: Yes, bootloader reserved the
        //   memory for us
        unsafe { transmute::<u64, &'static KernelArgs>(argc as u64) };
    // Parse the command line arguments:

    log::info!(
        "Parsing command line arguments: {:p}...",
        kernel_args.command_line
    );
    let cmdline = CommandLineArguments::from_str(kernel_args.command_line);
    // Initialize cmdline arguments as global
    crate::CMDLINE.call_once(move || cmdline);
    // Initialize kernel arguments as global
    crate::KERNEL_ARGS.call_once(move || kernel_args);

    log::info!("Initializing VSpace");
    // Needs to be done before we switch address space
    lazy_static::initialize(&vspace::INITIAL_VSPACE);

    log::info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    // Parse memory map provided by UEFI, create an initial emergency memory
    // manager with a little bit of memory so we can do some early allocations.
    let (emanager, memory_regions) = memory::process_uefi_memory_regions();

    log::info!("Initializing memory manager");
    let mut dyn_mem = PerCoreMemory::new(emanager, 0);

    // Make `dyn_mem` a static reference:
    let static_dyn_mem =
        // Safety:
        // - The initial stack of the core will never get deallocated (hence
        //   'static is fine)
        // - TODO(safety): aliasing rules is broken here (we have mut dyn_mem
        //   while we have now make a &'static to the same object)
        unsafe { core::mem::transmute::<&PerCoreMemory, &'static PerCoreMemory>(&dyn_mem) };

    log::info!("setting up KCB");
    // Construct the per-core state object that is accessed through the kernel
    // "core-local-storage" gs-register:
    let mut arch = kcb::AArch64Kcb::new(static_dyn_mem);
    // Make `arch` a static reference:
    let static_kcb =
        // Safety:
        // - The initial stack of the core will never get deallocated (hence
        //   'static is fine)
        // - TODO(safety): aliasing rules is broken here (we have mut dyn_mem
        //   while we have now make a &'static to the same object)
        unsafe { core::mem::transmute::<&mut kcb::AArch64Kcb, &'static mut kcb::AArch64Kcb>(&mut arch) };

    log::info!("installing the KCB");
    static_kcb.install();
    // Make sure we don't drop arch, dyn_mem and anything in it, they are on the
    // init stack which remains allocated, we can not reclaim this stack or
    // return from _start.

    log::info!("forgetting arch");
    core::mem::forget(arch);

    log::warn!("todo: initialize serial (maybe not needed?)!\n"); //irq::init_apic();serial::init();
    log::warn!("todo: initialize gic!\n"); //irq::init_apic();

    #[cfg(all(
        feature = "integration-test",
        any(feature = "test-double-fault", feature = "cause-double-fault")
    ))]
    debug::cause_double_fault();

    //assert!(acpi::init().is_ok());
    // Initialize atopology crate and sanity check machine size
    crate::environment::init_topology();

    // Identify NUMA region for physical memory (needs topology)
    let annotated_regions = identify_numa_affinity(memory_regions);

    // Initialize GlobalMemory (lowest level memory allocator).
    let global_memory = unsafe {
        // Safety:
        // - Annotated regions contains correct information
        GlobalMemory::new(annotated_regions).unwrap()
    };
    // Also GlobalMemory should live forver, (we hand out a reference to
    // `global_memory` to every core) that's fine since it is allocated on our
    // BSP init stack (which isn't reclaimed):
    let global_memory_static =
        unsafe { core::mem::transmute::<&GlobalMemory, &'static GlobalMemory>(&global_memory) };

    // Make sure our BSP core has a reference to GlobalMemory
    dyn_mem.set_global_mem(&global_memory_static);

    // Initializes persistent memory
    let annotated_regions = memory::init_persistent_memory();
    let global_memory = if annotated_regions.len() > 0 {
        unsafe {
            // Safety:
            // - Annotated regions contains correct information
            GlobalMemory::new(annotated_regions).unwrap()
        }
    } else {
        GlobalMemory::default()
    };
    // Also GlobalMemory should live forver, (we hand out a reference to
    // `global_memory` to every core) that's fine since it is allocated on our
    // BSP init stack (which isn't reclaimed):
    let global_memory_static =
        // Safety:
        // -'static: Lives on init stack (not deallocated)
        // - No mut alias to it
        unsafe { core::mem::transmute::<&GlobalMemory, &'static GlobalMemory>(&global_memory) };

    // Make sure our BSP core has a reference to GlobalMemory
    dyn_mem.set_global_pmem(&global_memory_static);
    core::mem::forget(dyn_mem);

    // Create the global operation log and first replica and store it (needs
    // TLS)
    let log: Arc<Log<Op>> = Arc::try_new(Log::<Op>::new(LARGE_PAGE_SIZE))
        .expect("Not enough memory to initialize system");
    let bsp_replica = Replica::<KernelNode>::new(&log);
    let local_ridx = bsp_replica.register().unwrap();
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

    // Intialize PCI
    // crate::pci::init();

    // Initialize processes
    lazy_static::initialize(&process::PROCESS_TABLE);
    crate::nrproc::register_thread_with_process_replicas();

    #[cfg(feature = "gdb")]
    {
        lazy_static::initialize(&gdb::GDB_STUB);
        // Safety:
        // - IDT is set-up, interrupts are working
        // - Only a breakpoint to wait for debugger to attach
        //unsafe { x86::int!(1) }; // Cause a debug interrupt to go to the `gdb::event_loop()`
    }

    #[cfg(feature = "rackscale")]
    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.mode == crate::cmdline::Mode::Client)
    {
        let _ = spin::lazy::Lazy::force(&rackscale::RPC_CLIENT);
    }

    // Bring up the rest of the system (needs topology, APIC, and global memory)
    coreboot::boot_app_cores(log.clone(), bsp_replica, fs_logs, fs_replica);

    log::info!("jumping into main...");
    // Done with initialization, now we go in the arch-independent part:
    let _r = crate::main();

    log::error!("Returned from main, shutting down...");
    halt();
    //debug::shutdown(ExitReason::ReturnFromMain);
}
