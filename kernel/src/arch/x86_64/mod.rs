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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::transmute;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use apic::ApicDriver;
use arrayvec::ArrayVec;
use cnr::Log as MlnrLog;
use cnr::Replica as MlnrReplica;
use driverkit::DriverControl;
use fallible_collections::FallibleVecGlobal;
use fallible_collections::TryClone;
use klogger::sprint;
use log::{debug, error, info, trace};
use node_replication::{Log, Replica};
use x86::bits64::paging::PAddr;
use x86::{controlregs, cpuid};

use crate::cmdline::CommandLineArguments;
use crate::fallible_string::FallibleString;
use crate::fs::cnrfs::MlnrKernelNode;
use crate::fs::cnrfs::Modify;
use crate::kcb::PerCoreMemory;
use crate::memory::global::{GlobalMemory, MAX_PHYSICAL_REGIONS};
use crate::memory::vspace::MapAction;
use crate::memory::{mcache, Frame, BASE_PAGE_SIZE, KERNEL_BASE};
use crate::nr::{KernelNode, Op};
use crate::stack::OwnedStack;
use crate::ExitReason;
use uefi::table::boot::MemoryType;

pub mod acpi;
pub mod coreboot;
pub mod debug;
pub mod gdt;
pub mod irq;
pub mod kcb;
pub mod memory;
pub mod process;
#[cfg(feature = "rackscale")]
pub mod rackscale;
pub mod signals;
pub mod syscall;
pub mod timer;
pub mod tlb;
pub mod vspace;

pub use bootloader_shared::*;

mod gdb;
mod isr;
mod serial;
mod tls;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;

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

/// Construct the driver object to manipulate the interrupt controller (XAPIC)
fn init_apic() {
    let mut apic = irq::LOCAL_APIC.borrow_mut();
    // Attach the driver to take control of the APIC:
    info!("before attach");
    apic.attach();

    info!(
        "x2APIC id: {}, logical_id: {}, version: {:#x}, is bsp: {}",
        apic.id(),
        apic.logical_id(),
        apic.version(),
        apic.bsp()
    );
}

struct AppCoreArgs {
    _mem_region: Frame,
    _pmem_region: Option<Frame>,
    global_memory: &'static GlobalMemory,
    global_pmem: &'static GlobalMemory,
    thread: atopology::ThreadId,
    node: atopology::NodeId,
    _log: Arc<Log<'static, Op>>,
    replica: Arc<Replica<'static, KernelNode>>,
    fs_replica: Arc<MlnrReplica<'static, MlnrKernelNode>>,
}

/// Entry point for application cores. This is normally called from `start_ap.S`.
///
/// This is almost identical to `_start` which is initializing the BSP core
/// (and called from UEFI instead).
fn start_app_core(args: Arc<AppCoreArgs>, initialized: &AtomicBool) {
    enable_sse();
    enable_fsgsbase();
    assert_required_cpu_features();
    syscall::enable_fast_syscalls();
    irq::disable();

    unsafe {
        gdt::setup_early_gdt();
        irq::setup_early_idt();
    };
    let start = rawtime::Instant::now();

    let emanager = mcache::FrameCacheEarly::new(args.node);
    let arch = kcb::Arch86Kcb::new();
    let mut kcb = PerCoreMemory::<kcb::Arch86Kcb>::new(emanager, arch, args.node);

    kcb.set_global_mem(args.global_memory);
    kcb.set_mem_manager(mcache::FrameCacheSmall::new(args.node));

    if args.global_pmem.node_caches.len() > 0 {
        kcb.set_global_pmem(args.global_pmem);
        kcb.set_pmem_manager(mcache::FrameCacheSmall::new(args.node));
    }

    let static_kcb = unsafe {
        core::mem::transmute::<
            &mut PerCoreMemory<kcb::Arch86Kcb>,
            &'static mut PerCoreMemory<kcb::Arch86Kcb>,
        >(&mut kcb)
    };
    kcb::init_kcb(static_kcb);

    static_kcb.arch.set_interrupt_stacks(
        OwnedStack::new(128 * BASE_PAGE_SIZE),
        OwnedStack::new(128 * BASE_PAGE_SIZE),
        OwnedStack::new(128 * BASE_PAGE_SIZE),
    );
    static_kcb
        .arch
        .set_syscall_stack(OwnedStack::new(128 * BASE_PAGE_SIZE));
    static_kcb
        .arch
        .set_save_area(Box::pin(kpi::x86_64::SaveArea::empty()));
    static_kcb.install();
    // Install thread-local storage for BSP

    if let Some(tls_args) = crate::KERNEL_ARGS.get().and_then(|k| k.tls_info.as_ref()) {
        use tls::ThreadControlBlock;
        unsafe {
            // Safety for `ThreadControlBlock::init`:
            // - we called `enable_fsgsbase()`: yes see above
            // - after static_kcb.install(): yes (otherwise fs is reset)
            // - TLS is uninitialized:
            assert!(
                x86::bits64::segmentation::rdfsbase() == 0x0,
                "BIOS/UEFI initializes `fs` with 0x0"
            );
            let tcb =
                ThreadControlBlock::init(tls_args).expect("Unable to initialize TLS during init");
            kcb.arch.tls_base = tcb;
        }
    }
    init_apic();
    serial::SerialControl::set_print_buffer(
        String::try_with_capacity(128).expect("Not enough memory to initialize system"),
    );
    core::mem::forget(kcb);

    {
        let local_ridx = args.replica.register().unwrap();
        crate::nr::NR_REPLICA.call_once(|| (args.replica.clone(), local_ridx));
        crate::nrproc::register_thread_with_process_replicas();
        crate::fs::cnrfs::init_cnrfs_on_thread(args.fs_replica.clone());

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

    crate::scheduler::schedule()
}

/// Initialize the rest of the cores in the system.
///
/// # Arguments
/// - `kernel_binary` - A slice of the kernel binary.
/// - `kernel_args` - Intial arguments as passed by UEFI to the kernel.
/// - `global_memory` - Memory allocator collection.
/// - `log` - A reference to the operation log.
/// - `bsp_replica` - Replica that the BSP core created and is registered to.
///
/// # Notes
/// Dependencies for calling this function are:
///  - Initialized ACPI
///  - Initialized topology
///  - Local APIC driver
fn boot_app_cores(
    log: Arc<Log<'static, Op>>,
    bsp_replica: Arc<Replica<'static, KernelNode>>,
    fs_logs: Vec<Arc<MlnrLog<'static, Modify>>>,
    fs_replica: Arc<MlnrReplica<'static, MlnrKernelNode>>,
) {
    use crate::memory::backends::PhysicalPageProvider;

    let bsp_thread = atopology::MACHINE_TOPOLOGY.current_thread();
    let kcb = kcb::get_kcb();
    debug_assert_eq!(*crate::kcb::NODE_ID, 0, "The BSP core is not on node 0?");

    // Let's go with one replica per NUMA node for now:
    let numa_nodes = core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes());

    let mut replicas: Vec<Arc<Replica<'static, KernelNode>>> =
        Vec::try_with_capacity(numa_nodes).expect("Not enough memory to initialize system");
    let mut fs_replicas: Vec<Arc<MlnrReplica<'static, MlnrKernelNode>>> =
        Vec::try_with_capacity(numa_nodes).expect("Not enough memory to initialize system");

    // Push the replica for node 0
    debug_assert!(replicas.capacity() >= 1, "No re-allocation.");
    replicas.push(bsp_replica);
    debug_assert!(fs_replicas.capacity() >= 1, "No re-allocation.");
    fs_replicas.push(fs_replica);

    for node in 1..numa_nodes {
        kcb.set_mem_affinity(node as atopology::NodeId)
            .expect("Can't set affinity");

        debug_assert!(replicas.capacity() > node, "No re-allocation.");
        replicas.push(Replica::<'static, KernelNode>::new(&log));

        debug_assert!(fs_replicas.capacity() > node, "No re-allocation.");
        fs_replicas.push(MlnrReplica::new(
            fs_logs
                .try_clone()
                .expect("Not enough memory to initialize system"),
        ));

        kcb.set_mem_affinity(0).expect("Can't set affinity");
    }

    let global_memory = kcb
        .physical_memory
        .gmanager
        .expect("boot_app_cores requires kcb.gmanager");

    let global_pmem = kcb
        .pmem_memory
        .gmanager
        .expect("boot_app_cores requires kcb.pmem_memory.gmanager");

    // For now just boot everything, except ourselves
    // Create a single log and one replica...
    let threads_to_boot = atopology::MACHINE_TOPOLOGY
        .threads()
        .filter(|t| t != &bsp_thread);

    for thread in threads_to_boot {
        let node = thread.node_id.unwrap_or(0);
        trace!("Booting {:?} on node {}", thread, node);
        kcb.set_mem_affinity(node).expect("Can't set affinity");

        // A simple stack for the app core (non bootstrap core)
        let coreboot_stack: OwnedStack = OwnedStack::new(BASE_PAGE_SIZE * 512);
        let mem_region = global_memory.node_caches[node as usize]
            .lock()
            .allocate_large_page()
            .expect("Can't allocate large page");
        let pmem_region = match global_pmem.node_caches.len() == numa_nodes {
            true => {
                kcb.set_pmem_affinity(node).expect("Can't set affinity");
                Some(
                    global_pmem.node_caches[node as usize]
                        .lock()
                        .allocate_large_page()
                        .expect("Can't allocate large page"),
                )
            }
            false => None,
        };

        let initialized: AtomicBool = AtomicBool::new(false);
        let arg: Arc<AppCoreArgs> = Arc::try_new(AppCoreArgs {
            _mem_region: mem_region,
            _pmem_region: pmem_region,
            node,
            global_memory,
            global_pmem,
            thread: thread.id,
            _log: log.clone(),
            replica: replicas[node as usize]
                .try_clone()
                .expect("Not enough memory to initialize system"),
            fs_replica: fs_replicas[node as usize]
                .try_clone()
                .expect("Not enough memory to initialize system"),
        })
        .expect("Not enough memory to initialize system");

        unsafe {
            coreboot::initialize(
                thread.apic_id(),
                start_app_core,
                arg.clone(),
                &initialized,
                &coreboot_stack,
            );

            // Wait until core is up or we time out
            let start = rawtime::Instant::now();
            loop {
                // Did the core signal us initialization completed?
                if initialized.load(Ordering::SeqCst) {
                    break;
                }

                // Have we waited long enough?
                if start.elapsed().as_secs() > 1 {
                    panic!("Core {:?} didn't boot properly...", thread.apic_id());
                }

                core::hint::spin_loop();
            }
        }
        core::mem::forget(coreboot_stack);

        assert!(initialized.load(Ordering::SeqCst));
        debug!("Core {:?} has started", thread.apic_id());
        kcb.set_mem_affinity(0).expect("Can't set affinity");
    }

    core::mem::forget(replicas);
}

/// Annotate all physical memory frames we got from UEFI with NUMA affinity by
/// walking through every region `memory_regions` and build subregions
/// that are constructed with the correct NUMA affinity.
///
/// We split frames in `memory_regions` in case they overlap multiple NUMA regions,
/// and let's hope it all fits in `annotated_regions`.
///
/// This really isn't the most efficient algorithm we could've built but we
/// only run this once and don't expect thousands of NUMA nodes or
/// memory regions anyways.
///
/// # Notes
/// There are some implicit assumptions here that a memory region always has
/// just one affinity -- which is also what `topology` assumes.
fn identify_numa_affinity(
    memory_regions: &ArrayVec<Frame, MAX_PHYSICAL_REGIONS>,
    annotated_regions: &mut ArrayVec<Frame, MAX_PHYSICAL_REGIONS>,
) {
    if atopology::MACHINE_TOPOLOGY.num_nodes() > 0 {
        for orig_frame in memory_regions.iter() {
            for node in atopology::MACHINE_TOPOLOGY.nodes() {
                // trying to find a NUMA memory affinity that contains the given `orig_frame`
                for affinity_region in node.memory() {
                    if !affinity_region.is_hotplug_region() {
                        match affinity_region
                            .contains(orig_frame.base.into(), orig_frame.end().into())
                        {
                            (_, mid, _) => {
                                if mid.0 > 0 {
                                    let mid_paddr = (PAddr::from(mid.0), PAddr::from(mid.1));
                                    let annotated_frame = Frame::from_range(mid_paddr, node.id);
                                    trace!("Identified NUMA region for {:?}", annotated_frame);
                                    assert!(!annotated_regions.is_full());
                                    annotated_regions.push(annotated_frame);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // We are not running on a NUMA machine,
        // so we just assume everything as node#0
        // (and copy from original memory regions):
        annotated_regions
            .try_extend_from_slice(memory_regions.as_slice())
            .expect("Can't initialize annotated regions");
    }

    // Sanity check our code the sum of total bytes in `annotated_regions`
    // should be the equal to the sum of bytes in `memory_regions`:
    assert_eq!(
        annotated_regions.iter().fold(0, |sum, f| sum + f.size()),
        memory_regions.iter().fold(0, |sum, f| sum + f.size())
    );
}

/// Map the persistent memory addresses to the vspace.
///
/// # TODO
/// This is a temporary hack until the bootloader shows us the persistent regions
/// when we query the uefi memory map. For some reason they don't show up with
/// current qemu edk2 OVMF builds. So we query ACPI directly here to find them.
fn map_physical_persistent_memory() {
    use atopology::MemoryType;
    let desc_iter = atopology::MACHINE_TOPOLOGY.persistent_memory();
    for entry in desc_iter {
        if entry.phys_start == 0x0 {
            debug!("Don't map memory entry at physical zero? {:#?}", entry);
            continue;
        }

        // Compute physical base and size for the region we're about to map
        let phys_range_start = PAddr::from(entry.phys_start);
        let size = entry.page_count as usize * BASE_PAGE_SIZE;
        let phys_range_end =
            PAddr::from(entry.phys_start + entry.page_count * BASE_PAGE_SIZE as u64);

        if phys_range_start.as_u64() <= 0xfee00000u64 && phys_range_end.as_u64() >= 0xfee00000u64 {
            debug!("{:?} covers APIC range, ignore for now.", entry);
            continue;
        }

        let rights: MapAction = match entry.ty {
            MemoryType::PERSISTENT_MEMORY => MapAction::ReadWriteKernel,
            _ => {
                error!("Unknown memory type, what should we do? {:#?}", entry);
                MapAction::None
            }
        };

        debug!(
            "Doing {:?} on {:#x} -- {:#x}",
            rights, phys_range_start, phys_range_end
        );
        if rights != MapAction::None && entry.ty == MemoryType::PERSISTENT_MEMORY {
            vspace::INITIAL_VSPACE
                .lock()
                .map_identity(phys_range_start, size, rights)
                .expect("Unable to add PMem address to user-space");

            vspace::INITIAL_VSPACE
                .lock()
                .map_identity_with_offset(PAddr::from(KERNEL_BASE), phys_range_start, size, rights)
                .expect("Unable to add PMem address to Kernel-space");
        }
    }
}

/// Entry function that is called from UEFI
/// At this point we are in x86-64 (long) mode,
/// We have a simple GDT, our address space, and stack set-up.
/// The argc argument is abused as a pointer ot the KernelArgs struct
/// passed by UEFI.
#[cfg(target_os = "none")]
#[start]
#[no_mangle]
fn _start(argc: isize, _argv: *const *const u8) -> isize {
    use crate::memory::LARGE_PAGE_SIZE;

    sprint!("\r\n");
    enable_sse();
    enable_fsgsbase();
    unsafe {
        gdt::setup_early_gdt();
        irq::setup_early_idt();
    };

    // Make sure these constants are initialized early, for proper time accounting (otherwise because
    // they are lazy_static we may not end up using them until way later).
    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // We construct a &'static mut for KernelArgs (mut is just because of `mm_iter`)
    let kernel_args: &'static mut KernelArgs =
        unsafe { transmute::<u64, &'static mut KernelArgs>(argc as u64) };

    // Parse the command line arguments
    let cmdline = CommandLineArguments::from_str(kernel_args.command_line);
    // Initialize cmdline arguments as global
    crate::CMDLINE.call_once(|| cmdline);

    klogger::init(
        crate::CMDLINE.get().map(|c| c.log_filter).unwrap_or("info"),
        debug::SERIAL_PRINT_PORT.load(Ordering::Relaxed),
    )
    .expect("Can't set-up logging");

    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    // At this point we should be able to handle exceptions:
    #[cfg(feature = "cause-pfault-early")]
    debug::cause_pfault();
    #[cfg(feature = "cause-gpfault-early")]
    debug::cause_gpfault();

    // Figure out what this machine supports,
    // fail if it doesn't have what we need.
    assert_required_cpu_features();
    syscall::enable_fast_syscalls();

    // Initializes the serial console.
    // (this is already done in a very basic form by klogger/init_logging())
    debug::init();

    // Set up early memory management
    //
    // We walk the memory regions given to us by uefi, since this consumes
    // the UEFI iterator we copy the frames into a `ArrayVec`.
    //
    // Ideally, if this works, we should end up with an early FrameCacheSmall
    // that has a small amount of space we can allocate from, and a list of (yet) unmaintained
    // regions of memory.
    let mut emanager: Option<mcache::FrameCacheEarly> = None;
    let mut memory_regions: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
    for region in &mut kernel_args.mm_iter {
        if region.ty == MemoryType::CONVENTIONAL {
            debug!("Found physical memory region {:?}", region);

            let base: PAddr = PAddr::from(region.phys_start);
            let size: usize = region.page_count as usize * BASE_PAGE_SIZE;
            let f = Frame::new(base, size, 0);

            const ONE_MIB: usize = 1 * 1024 * 1024;
            const EARLY_MEMORY_CAPACITY: usize = 32 * 1024 * 1024;
            if base.as_usize() >= ONE_MIB {
                if size > EARLY_MEMORY_CAPACITY && emanager.is_none() {
                    // This seems like a good frame for the early allocator on the BSP core.
                    // We don't have NUMA information yet so we'd hope that on
                    // a NUMA machine this memory will be on node 0.
                    // Ideally `mem_iter` is ordered by physical address which would increase
                    // our chances, but the UEFI spec doesn't guarantee anything :S
                    let (early_frame, high) = f.split_at(EARLY_MEMORY_CAPACITY);
                    emanager = Some(mcache::FrameCacheEarly::new_with_frame(0, early_frame));

                    if high != Frame::empty() {
                        assert!(!memory_regions.is_full());
                        memory_regions.push(high);
                    }
                } else {
                    assert!(!memory_regions.is_full());
                    memory_regions.push(f);
                }
            } else {
                // Ignore all physical memory below 1 MiB
                // because it's not worth the hassle of dealing with it
                // Some of the memory here will be used by coreboot, there we just assume
                // the memory is free for us to use -- so in case someone
                // wants to change it have a look there first!
            }
        }
    }
    // Initialize kernel arguments as global
    crate::KERNEL_ARGS.call_once(|| kernel_args);

    let emanager = emanager
        .expect("Couldn't build an early physical memory manager, increase system main memory?");
    // Needs to be done before we switch address space
    lazy_static::initialize(&vspace::INITIAL_VSPACE);
    let arch = kcb::Arch86Kcb::new();

    // Construct the Kcb so we can access these things later on in the code
    let mut kcb = PerCoreMemory::new(emanager, arch, 0);
    kcb::init_kcb(&mut kcb);
    debug!("Memory allocation should work at this point...");
    let static_kcb = unsafe {
        core::mem::transmute::<
            &mut PerCoreMemory<kcb::Arch86Kcb>,
            &'static mut PerCoreMemory<kcb::Arch86Kcb>,
        >(&mut kcb)
    };

    // Let's finish KCB initialization (easier as we have alloc now):
    static_kcb.arch.set_interrupt_stacks(
        OwnedStack::new(128 * BASE_PAGE_SIZE),
        OwnedStack::new(128 * BASE_PAGE_SIZE),
        OwnedStack::new(128 * BASE_PAGE_SIZE),
    );
    static_kcb
        .arch
        .set_syscall_stack(OwnedStack::new(128 * BASE_PAGE_SIZE));
    static_kcb
        .arch
        .set_save_area(Box::pin(kpi::x86_64::SaveArea::empty()));
    static_kcb.install();

    // Install thread-local storage for BSP
    if let Some(tls_args) = &kernel_args.tls_info {
        use tls::ThreadControlBlock;
        unsafe {
            // Safety for `ThreadControlBlock::init`:
            // - we called `enable_fsgsbase()`: yes see above
            // - after static_kcb.install(): yes (otherwise fs is reset)
            // - TLS is uninitialized:
            assert!(
                x86::bits64::segmentation::rdfsbase() == 0x0,
                "BIOS/UEFI initializes `fs` with 0x0"
            );
            let tcb =
                ThreadControlBlock::init(tls_args).expect("Unable to initialize TLS during init");
            kcb::get_kcb().arch.tls_base = tcb;
        }
    }
    serial::SerialControl::set_print_buffer(
        String::try_with_capacity(128).expect("Not enough memory to initialize system"),
    );
    init_apic();

    // Make sure we don't drop the KCB and anything in it,
    // the kcb is on the init stack and remains allocated on it,
    // this is (probably) fine as we never reclaim this stack or
    // return to _start.
    core::mem::forget(kcb);

    #[cfg(all(
        feature = "integration-test",
        any(feature = "test-double-fault", feature = "cause-double-fault")
    ))]
    debug::cause_double_fault();

    // Initialize the ACPI sub-system (needs alloc)
    {
        let r = acpi::init();
        assert!(r.is_ok());
    }

    // Initialize the machine topology (needs ACPI and alloc):
    {
        lazy_static::initialize(&atopology::MACHINE_TOPOLOGY);
        info!("Topology parsed");

        trace!("{:#?}", *atopology::MACHINE_TOPOLOGY);
        let nodes = atopology::MACHINE_TOPOLOGY.num_nodes();
        let cores = atopology::MACHINE_TOPOLOGY.num_threads();
        assert!(
            MAX_NUMA_NODES >= nodes,
            "We don't support more NUMA nodes than `MAX_NUMA_NODES."
        );
        assert!(
            MAX_CORES >= cores,
            "We don't support more cores than `MAX_CORES."
        );
        assert!(
            cnr::MAX_REPLICAS_PER_LOG >= nodes,
            "We don't support as many replicas as we have NUMA nodes."
        );
        assert!(
            node_replication::MAX_REPLICAS_PER_LOG >= nodes,
            "We don't support as many replicas as we have NUMA nodes."
        );
    }

    // Identify NUMA region for physical memory (needs topology)
    let mut annotated_regions = ArrayVec::new();
    identify_numa_affinity(&memory_regions, &mut annotated_regions);
    // Make sure we don't accidentially use the memory_regions but rather,
    // use the correctly `annotated_regions` now!
    drop(memory_regions);

    // Initialize memory allocators (needs annotated memory regions, KCB)
    // the memory for those allocators needs to be local to the region.
    //  - Each `annotated_region` should be backed at the lowest level by a buddy allocator
    //  - For every node we should have one FrameCacheLarge
    // all this work is done in GlobalMemory.
    //
    // This call is safe here because we assume that our `annotated_regions` is correct.
    let global_memory = unsafe { GlobalMemory::new(annotated_regions).unwrap() };
    // Also GlobalMemory should live forver, (we hand out a reference to `global_memory` to every core)
    // that's fine since it is allocated on our BSP init stack (which isn't reclaimed):
    let global_memory_static =
        unsafe { core::mem::transmute::<&GlobalMemory, &'static GlobalMemory>(&global_memory) };

    // Make sure our BSP core has a reference to GlobalMemory
    {
        let kcb = kcb::get_kcb();
        kcb.set_global_mem(&global_memory_static);
        let tcache = mcache::FrameCacheSmall::new(0);
        kcb.set_mem_manager(tcache);
    }

    // 1. Discover persistent memory using topology information.
    // 2. Identity map the persistent memoy regions to user and kernel space.
    // 3. Find the NUMA-affinity for each persistent memory region.
    // 4. Use the region and affinity region to bind an allocator to the regions.
    map_physical_persistent_memory();

    let mut memory_regions: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
    let mut pmem_iter = atopology::MACHINE_TOPOLOGY.persistent_memory();
    for region in &mut pmem_iter {
        if region.ty == atopology::MemoryType::PERSISTENT_MEMORY {
            debug!("Found physical memory region {:?}", region);

            let base: PAddr = PAddr::from(region.phys_start);
            let size: usize = region.page_count as usize * BASE_PAGE_SIZE;
            let f = Frame::new(base, size, 0);

            assert!(!memory_regions.is_full());
            memory_regions.push(f);
        }
    }
    let mut annotated_regions = ArrayVec::new();
    identify_numa_affinity(&memory_regions, &mut annotated_regions);
    drop(memory_regions);
    annotated_regions.sort_by(|&a, &b| a.affinity.partial_cmp(&b.affinity).unwrap());

    // This call is safe here because we assume that our `annotated_regions` is correct.
    let global_memory = match annotated_regions.len() > 0 {
        true => unsafe { GlobalMemory::new(annotated_regions).unwrap() },
        false => GlobalMemory::default(),
    };
    // Also GlobalMemory should live forver, (we hand out a reference to `global_memory` to every core)
    // that's fine since it is allocated on our BSP init stack (which isn't reclaimed):
    let global_memory_static =
        unsafe { core::mem::transmute::<&GlobalMemory, &'static GlobalMemory>(&global_memory) };

    // Make sure our BSP core has a reference to GlobalMemory
    {
        let kcb = kcb::get_kcb();
        kcb.set_global_pmem(&global_memory_static);
        let tcache = mcache::FrameCacheSmall::new(0);
        kcb.set_pmem_manager(tcache);
    }

    // Set-up interrupt routing drivers (I/O APIC controllers)
    irq::ioapic_initialize();

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
    crate::pci::init();

    // Initialize processes
    lazy_static::initialize(&process::PROCESS_TABLE);
    crate::nrproc::register_thread_with_process_replicas();

    #[cfg(feature = "gdb")]
    {
        lazy_static::initialize(&gdb::GDB_STUB);
        // Safety:
        // - IDT is set-up, interrupts are working
        // - Only a breakpoint to wait for debugger to attach
        unsafe { x86::int!(1) }; // Cause a debug interrupt to go to the `gdb::event_loop()`
    }

    #[cfg(feature = "rackscale")]
    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.mode == crate::cmdline::Mode::Client)
    {
        let _ = spin::lazy::Lazy::force(&rackscale::RPC_CLIENT);
    }

    // Bring up the rest of the system (needs topology, APIC, and global memory)
    boot_app_cores(log.clone(), bsp_replica, fs_logs, fs_replica);

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
