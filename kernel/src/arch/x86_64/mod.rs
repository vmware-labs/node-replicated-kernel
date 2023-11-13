// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Ignore dead and unused code in this arch when linking this with `unix`
// platform (for unit tests / clippy)
#![cfg_attr(not(target_os = "none"), allow(unused, dead_code))]

//! Contains initialization code for x86-64 cores.
//!
//! The purpose of the arch specific part is to initialize the machine to
//! a sane environment and then call the main() function.
//!
//! Unfortunately, lots of things have to happen to initialize a machine,
//! so roughly this file tries to do three things:
//!
//! - In `_start` (entry point from bootloader) we process the information
//!   we got from UEFI, and initialize the first core.
//! - Set-up system services like ACPI and physical memory management,
//!   parse the machine topology.
//! - Boot the rest of the system (see `start_app_core`).

use alloc::sync::Arc;
use core::mem::transmute;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

#[cfg(feature = "rackscale")]
use crate::nr::NR_LOG;
pub use bootloader_shared::*;
use cnr::Replica as MlnrReplica;
use fallible_collections::TryClone;
use klogger::sprint;
use log::{debug, error, info};
use node_replication::Replica;
use x86::{controlregs, cpuid};
#[cfg(not(feature = "rackscale"))]
use {crate::nr::Op, node_replication::Log};

use crate::cmdline::CommandLineArguments;
use crate::fs::cnrfs::MlnrKernelNode;
use crate::memory::global::GlobalMemory;
use crate::memory::mcache;
use crate::memory::per_core::PerCoreMemory;
use crate::nr::KernelNode;
use crate::ExitReason;

use coreboot::AppCoreArgs;
use memory::identify_numa_affinity;

pub mod acpi;
pub mod coreboot;
pub mod debug;
mod gdb;
pub mod gdt;
pub mod irq;
mod isr;
pub mod kcb;
pub mod memory;
pub mod process;
#[cfg(feature = "rackscale")]
pub mod rackscale;
mod serial;
pub mod signals;
pub mod syscall;
pub mod timer;
pub mod tlb;
mod tls;
pub mod vspace;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;
pub(crate) const MAX_MACHINES: usize = 16;

/// Make sure the machine supports what we require.
fn assert_required_cpu_features() {
    let cpuid = cpuid::CpuId::new();
    let fi = cpuid.get_feature_info();
    let has_apic = fi.as_ref().map_or(false, |f| f.has_apic());
    let has_x2apic = fi.as_ref().map_or(false, |f| f.has_x2apic());
    let has_tsc = fi.as_ref().map_or(false, |f| f.has_tsc());
    let has_syscalls = fi.as_ref().map_or(false, |f| f.has_sysenter_sysexit());
    let has_pae = fi.as_ref().map_or(false, |f| f.has_pae());
    let has_msr = fi.as_ref().map_or(false, |f| f.has_msr());

    let has_sse = fi.as_ref().map_or(false, |f| f.has_sse());
    let has_sse3 = fi.as_ref().map_or(false, |f| f.has_sse3());
    let _has_avx = fi.as_ref().map_or(false, |f| f.has_avx());
    let has_osfxsr = fi.as_ref().map_or(false, |f| f.has_fxsave_fxstor());

    assert!(has_tsc, "No RDTSC? Run on a more modern machine!");
    assert!(has_sse, "No SSE? Run on a more modern machine!");
    assert!(has_osfxsr, "No fxsave? Run on a more modern machine!");
    assert!(has_sse3, "No SSE3? Run on a more modern machine!"); //TBD

    //assert!(has_avx, "No AVX? Run on a more modern machine!");

    assert!(has_apic, "No APIC? Run on a more modern machine!");
    assert!(has_x2apic, "No X2APIC? Run on a more modern machine!");
    assert!(has_syscalls, "No sysenter? Run on a more modern machine!");
    assert!(has_pae, "No PAE? Run on a more modern machine!");
    assert!(has_msr, "No MSR? Run on a more modern machine!");
}

/// Enable SSE functionality and disable the old x87 FPU.
/// (yes this goes against conventional
/// wisdom that thinks SSE instructions in the
/// kernel are a bad idea)
///
/// # TODO
/// This is public because of the integration tests (and ideally shouldn't be).
pub(crate) fn enable_sse() {
    // Follow the protocol described in Intel SDM, 13.1.3 Initialization of the SSE Extensions
    unsafe {
        let mut cr4 = controlregs::cr4();
        // Operating system provides facilities for saving and restoring SSE state
        // using FXSAVE and FXRSTOR instructions
        cr4 |= controlregs::Cr4::CR4_ENABLE_SSE;
        // The operating system provides a SIMD floating-point exception (#XM) handler
        //cr4 |= x86::controlregs::Cr4::CR4_UNMASKED_SSE;
        controlregs::cr4_write(cr4);

        let mut cr0 = controlregs::cr0();
        // Disables emulation of the x87 FPU
        cr0 &= !controlregs::Cr0::CR0_EMULATE_COPROCESSOR;
        // Required for Intel 64 and IA-32 processors that support the SSE
        cr0 |= controlregs::Cr0::CR0_MONITOR_COPROCESSOR;
        controlregs::cr0_write(cr0);
    }
}

/// For our scheduler and KCB we enable the fs/gs base instructions on the machine
/// This allows us to conventiently read and write the fs and gs registers
/// with 64 bit values (otherwise it's a bit of a pain)
/// (used for our thread local storage implementation).
///
/// # TODO
/// This is public because of the integration tests (and ideally shouldn't be).
pub(crate) fn enable_fsgsbase() {
    unsafe {
        let mut cr4: controlregs::Cr4 = controlregs::cr4();
        cr4 |= controlregs::Cr4::CR4_ENABLE_FSGSBASE;
        controlregs::cr4_write(cr4)
    };
}

/// Goes to sleep / halts the core.
///
/// Interrupts are enabled before going to sleep.
pub(crate) fn halt() -> ! {
    unsafe {
        irq::enable();
        loop {
            x86::halt()
        }
    }
}

/// Entry point for application cores. This is normally called from `start_ap.S`.
///
/// This is almost identical to `_start` which is initializing the BSP core
/// (and called from UEFI instead).
pub(crate) fn start_app_core(args: Arc<AppCoreArgs>, initialized: &AtomicBool) {
    enable_sse();
    enable_fsgsbase();
    assert_required_cpu_features();
    syscall::enable_fast_syscalls();
    irq::disable();

    // Safety:
    // - We are at the beginning of basic core initialization and need a gdt/idt
    unsafe {
        gdt::setup_early_gdt();
        irq::setup_early_idt();
    };
    let start = rawtime::Instant::now();

    let emanager = mcache::FrameCacheEarly::new(args.node);
    let mut dyn_mem = PerCoreMemory::new(emanager, args.node);
    dyn_mem.set_global_mem(args.global_memory);
    if args.global_pmem.node_caches.len() > 0 {
        dyn_mem.set_global_pmem(args.global_pmem);
    }
    let static_dyn_mem =
        unsafe { core::mem::transmute::<&PerCoreMemory, &'static PerCoreMemory>(&mut dyn_mem) };
    core::mem::forget(dyn_mem);

    let mut kcb = kcb::Arch86Kcb::new(&static_dyn_mem);
    let static_kcb = unsafe {
        core::mem::transmute::<&mut kcb::Arch86Kcb, &'static mut kcb::Arch86Kcb>(&mut kcb)
    };
    core::mem::forget(kcb);
    static_kcb.install();
    irq::init_apic();
    serial::init();

    {
        let local_ridx = args.replica.register().unwrap();
        crate::nr::NR_REPLICA.call_once(|| (args.replica.clone(), local_ridx));

        #[cfg(feature = "rackscale")]
        if crate::CMDLINE
            .get()
            .map_or(false, |c| c.mode == crate::cmdline::Mode::Client)
        {
            crate::nrproc::register_thread_with_process_replicas();
            crate::arch::rackscale::client_state::create_client_rpc_shmem_buffers();
        }

        #[cfg(not(feature = "rackscale"))]
        crate::nrproc::register_thread_with_process_replicas();

        // For rackscale, only the controller needs cnrfs
        if let Some(core_fs_replica) = &args.fs_replica {
            crate::fs::cnrfs::init_cnrfs_on_thread(core_fs_replica.clone());
        }

        // Don't modify this line without adjusting `coreboot` integration test:
        info!(
            "Core #{} initialized (replica idx {:?}) in {:?}.",
            args.thread,
            local_ridx,
            start.elapsed()
        );
    }

    // Signals to BSP core that we're done initializing.
    initialized.store(true, Ordering::SeqCst);

    #[cfg(feature = "rackscale")]
    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.mode == crate::cmdline::Mode::Controller)
    {
        crate::arch::rackscale::controller::run()
    }
    crate::scheduler::schedule()
}

/// Entry function that is called from UEFI At this point we are in x86-64
/// (long) mode, We have a simple GDT, our address space, and stack set-up. The
/// argc argument is abused as a pointer ot the KernelArgs struct passed by
/// UEFI.
#[cfg(target_os = "none")]
#[start]
#[no_mangle]
fn _start(argc: isize, _argv: *const *const u8) -> isize {
    #[cfg(not(feature = "rackscale"))]
    use crate::memory::LARGE_PAGE_SIZE;

    // Very early init:
    sprint!("\r\n");
    sprint!("NRK booting on x86_64...\r\n");
    enable_sse();
    enable_fsgsbase();
    unsafe {
        gdt::setup_early_gdt();
        irq::setup_early_idt();
    };

    // Make sure these constants are initialized early, for proper time
    // accounting (otherwise because they are lazy_static we may not end up
    // using them until way later).
    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    //
    // Almost early init, parse supplied arguments:
    //

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
    let cmdline = match CommandLineArguments::from_str(kernel_args.command_line) {
        Ok(cmdline) => cmdline,
        Err(err) => {
            sprint!("Parsing the commandline failed ({err}). Halting...\r\n");
            halt();
        }
    };

    // Initialize cmdline arguments as global
    crate::CMDLINE.call_once(move || cmdline);
    // Initialize kernel arguments as global
    crate::KERNEL_ARGS.call_once(move || kernel_args);

    // Needs to be done before we switch address space
    lazy_static::initialize(&vspace::INITIAL_VSPACE);

    klogger::init(
        crate::CMDLINE.get().map(|c| c.log_filter).unwrap_or("info"),
        debug::SERIAL_PRINT_PORT.load(Ordering::Relaxed) as u64,
    )
    .expect("Can't set-up logging");

    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    // At this point we should be able to handle exceptions (this is for testing
    // only)
    #[cfg(feature = "cause-pfault-early")]
    debug::cause_pfault();
    #[cfg(feature = "cause-gpfault-early")]
    debug::cause_gpfault();

    // Figure out what this machine supports, fail if it doesn't have what we
    // need. This happens here because we do have logging now so it's easier to
    // find out if something goes wrong.
    assert_required_cpu_features();
    syscall::enable_fast_syscalls();

    // Initializes the serial console. (this is already done in a very basic
    // form by klogger::init above, but now we do it for more ports)
    debug::init();

    #[cfg(feature = "rackscale")]
    {
        use crate::transport::shmem::SHMEM_INITIALIZED;
        lazy_static::initialize(&SHMEM_INITIALIZED);
    }

    // Parse memory map provided by UEFI, create an initial emergency memory
    // manager with a little bit of memory so we can do some early allocations.
    let (emanager, memory_regions) = memory::process_uefi_memory_regions();

    // Construct the per-core state so we can do dynamic allocation soon:
    let mut dyn_mem = PerCoreMemory::new(emanager, 0);
    // Make `dyn_mem` a static reference:
    let static_dyn_mem =
        // Safety:
        // - The initial stack of the core will never get deallocated (hence
        //   'static is fine)
        // - TODO(safety): aliasing rules is broken here (we have mut dyn_mem
        //   while we have now make a &'static to the same object)
        unsafe { core::mem::transmute::<&PerCoreMemory, &'static PerCoreMemory>(&dyn_mem) };
    // Construct the per-core state object that is accessed through the kernel
    // "core-local-storage" gs-register:
    let mut arch = kcb::Arch86Kcb::new(static_dyn_mem);
    // Make `arch` a static reference:
    let static_kcb =
        // Safety:
        // - The initial stack of the core will never get deallocated (hence
        //   'static is fine)
        // - TODO(safety): aliasing rules is broken here (we have mut dyn_mem
        //   while we have now make a &'static to the same object)
        unsafe { core::mem::transmute::<&mut kcb::Arch86Kcb, &'static mut kcb::Arch86Kcb>(&mut arch) };
    static_kcb.install();
    // Make sure we don't drop arch, dyn_mem and anything in it, they are on the
    // init stack which remains allocated, we can not reclaim this stack or
    // return from _start.
    core::mem::forget(arch);

    serial::init();
    irq::init_apic();
    // For testing only:
    #[cfg(all(
        feature = "integration-test",
        any(feature = "test-double-fault", feature = "cause-double-fault")
    ))]
    debug::cause_double_fault();
    // Initialize the ACPI sub-system (needs alloc)
    assert!(acpi::init().is_ok());
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

    #[cfg(feature = "rackscale")]
    {
        {
            use crate::transport::shmem::SHMEM;
            lazy_static::initialize(&SHMEM);

            if crate::CMDLINE
                .get()
                .map_or(false, |c| c.mode == crate::cmdline::Mode::Controller)
            {
                use crate::arch::rackscale::controller_state::CONTROLLER_SHMEM_CACHES;
                lazy_static::initialize(&CONTROLLER_SHMEM_CACHES);
                lazy_static::initialize(&crate::arch::rackscale::dcm::DCM_CLIENT);
            } else {
                use crate::arch::irq::{
                    REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR, REMOTE_TLB_WORK_PENDING_VECTOR,
                };

                // Setup to receive interrupts
                SHMEM.devices[0].enable_msix_vector(
                    REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR as usize,
                    0,
                    REMOTE_TLB_WORK_PENDING_VECTOR,
                );
                lazy_static::initialize(&rackscale::client_state::CLIENT_STATE);
                crate::arch::rackscale::client_state::create_client_rpc_shmem_buffers();
                log::info!("Finished inititializing client state & shmem buffer");
            }
        }
        // Initialize the workqueues used for distributed TLB shootdowns
        lazy_static::initialize(&crate::arch::tlb::RACKSCALE_CLIENT_WORKQUEUES);
        log::info!("Finished inititializing client work queues");
    }

    unsafe { vspace::init_large_objects_pml4() };

    // Set-up interrupt routing drivers (I/O APIC controllers)
    irq::ioapic_initialize();

    // Create the global operation log and first replica and store it (needs
    // TLS)
    #[cfg(not(feature = "rackscale"))]
    let (log, bsp_replica) = {
        let log: Arc<Log<Op>> = Arc::try_new(Log::<Op>::new(LARGE_PAGE_SIZE))
            .expect("Not enough memory to initialize system");
        let bsp_replica = Replica::<KernelNode>::new(&log);
        let local_ridx = bsp_replica.register().unwrap();
        crate::nr::NR_REPLICA.call_once(|| (bsp_replica.clone(), local_ridx));
        (log, bsp_replica)
    };

    // Starting to initialize file-system
    #[cfg(not(feature = "rackscale"))]
    let (fs_logs, fs_replica) = {
        let fs_logs = crate::fs::cnrfs::allocate_logs();
        let fs_logs_cloned = fs_logs
            .try_clone()
            .expect("Not enough memory to initialize system");
        // Construct the first replica
        let fs_replica = MlnrReplica::<MlnrKernelNode>::new(fs_logs_cloned);
        crate::fs::cnrfs::init_cnrfs_on_thread(fs_replica.clone());
        (fs_logs, Some(fs_replica))
    };

    // For rackscale, only the controller needs cnrfs
    #[cfg(feature = "rackscale")]
    let (fs_logs, fs_replica) = if crate::CMDLINE
        .get()
        .map_or(false, |c| c.mode == crate::cmdline::Mode::Controller)
    {
        let fs_logs = crate::fs::cnrfs::allocate_logs();
        let fs_logs_cloned = fs_logs
            .try_clone()
            .expect("Not enough memory to initialize system");
        // Construct the first replica
        let fs_replica = MlnrReplica::<MlnrKernelNode>::new(fs_logs_cloned);
        crate::fs::cnrfs::init_cnrfs_on_thread(fs_replica.clone());
        (fs_logs, Some(fs_replica))
    } else {
        use alloc::vec::Vec;
        (Vec::new(), None)
    };

    // Intialize PCI
    crate::pci::init();

    // Initialize processes
    lazy_static::initialize(&process::PROCESS_LOGS);

    #[cfg(not(feature = "rackscale"))]
    {
        lazy_static::initialize(&process::PROCESS_TABLE);
        crate::nrproc::register_thread_with_process_replicas();
    }

    #[cfg(feature = "rackscale")]
    let (log, bsp_replica) = {
        if crate::CMDLINE
            .get()
            .map_or(false, |c| c.mode == crate::cmdline::Mode::Client)
        {
            lazy_static::initialize(&process::PROCESS_TABLE);
            crate::nrproc::register_thread_with_process_replicas();
        }

        // this calls an RPC on the client, which is why we do this later in initialization than in non-rackscale
        lazy_static::initialize(&NR_LOG);

        // For rackscale, only the controller is going to create the base log.
        // All clients will use this to create replicas.
        let bsp_replica = Replica::<KernelNode>::new(&NR_LOG);
        let local_ridx = bsp_replica.register().unwrap();
        crate::nr::NR_REPLICA.call_once(|| (bsp_replica.clone(), local_ridx));
        (&NR_LOG.clone(), bsp_replica)
    };

    #[cfg(feature = "gdb")]
    {
        lazy_static::initialize(&gdb::GDB_STUB);
        // Safety:
        // - IDT is set-up, interrupts are working
        // - Only a breakpoint to wait for debugger to attach
        unsafe { x86::int!(1) }; // Cause a debug interrupt to go to the `gdb::event_loop()`
    }

    // Bring up the rest of the system (needs topology, APIC, and global memory)
    coreboot::boot_app_cores(log.clone(), bsp_replica, fs_logs, fs_replica);

    // Done with initialization, now we go in
    // the arch-independent part:
    let _r = crate::main();

    error!("Returned from main, shutting down...");
    debug::shutdown(ExitReason::ReturnFromMain);
}

/// For cores that advances the replica eagerly. This avoids additional IPI costs.
pub(crate) fn advance_fs_replica() {
    tlb::eager_advance_fs_replica();
}
