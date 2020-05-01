/// Test time facilities in the kernel.
#[cfg(all(feature = "integration-test", feature = "test-time"))]
pub fn xmain() {
    unsafe {
        let tsc = x86::time::rdtsc();
        let tsc2 = x86::time::rdtsc();

        let start = rawtime::Instant::now();
        let done = start.elapsed().as_nanos();
        // We do this twice because I think it traps the first time?
        let start = rawtime::Instant::now();
        let done = start.elapsed().as_nanos();
        sprintln!("rdtsc overhead: {:?} cycles", tsc2 - tsc);
        sprintln!("Instant overhead: {:?} ns", done);

        if cfg!(debug_assertions) {
            assert!(tsc2 - tsc <= 150, "rdtsc overhead big?");
            // TODO: should be less:
            assert!(done <= 300, "Instant overhead big?");
        } else {
            assert!(tsc2 - tsc <= 100);
            // TODO: should be less:
            assert!(done <= 150);
        }
    }
    arch::debug::shutdown(ExitReason::Ok);
}

/// Test time facilities in the kernel.
#[cfg(all(
    feature = "integration-test",
    feature = "test-timer",
    target_arch = "x86_64"
))]
pub fn xmain() {
    use apic::ApicDriver;
    use core::convert::TryInto;
    use core::sync::atomic::spin_loop_hint;
    use core::time::Duration;

    unsafe {
        let tsc = x86::time::rdtsc();

        {
            let kcb = crate::kcb::get_kcb();
            let mut apic = kcb.arch.apic();
            apic.tsc_enable();
            apic.tsc_set(tsc + 1_000_000_000);
        }

        // Don't change this line without changing
        // `s01_timer` in integration-tests.rs:
        info!("Setting the timer");

        let start = rawtime::Instant::now();
        crate::arch::irq::enable();
        while start.elapsed() < Duration::from_secs(1) {
            spin_loop_hint();
        }
        crate::arch::irq::disable();

        let done = start.elapsed().as_nanos();
    }
    arch::debug::shutdown(ExitReason::Ok);
}

/// Test that we can exit the machine.
#[cfg(all(feature = "integration-test", feature = "test-exit"))]
pub fn xmain() {
    arch::debug::shutdown(ExitReason::Ok);
}

/// Test the debug facility for page-faults.
#[cfg(all(feature = "integration-test", feature = "test-pfault"))]
#[inline(never)]
pub fn xmain() {
    use arch::debug;
    debug::cause_pfault();
}

/// Test the debug facility for general-protection-faults.
#[cfg(all(feature = "integration-test", feature = "test-gpfault"))]
pub fn xmain() {
    use arch::debug;
    debug::cause_gpfault();
}

/// Test allocation and deallocation of objects of various sizes.
#[cfg(all(feature = "integration-test", feature = "test-alloc"))]
pub fn xmain() {
    use alloc::vec::Vec;
    {
        let mut buf: Vec<u8> = Vec::with_capacity(0);
        // test allocation sizes from 0 .. 8192
        for i in 0..1024 {
            buf.push(i as u8);
        }
    } // Make sure we drop here.
    info!("small allocations work.");

    {
        let size: usize = x86::bits64::paging::BASE_PAGE_SIZE; // 0.03 MiB, 8 pages
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        for i in 0..size {
            buf.push(i as u8);
        }

        let size: usize = x86::bits64::paging::BASE_PAGE_SIZE * 256; // 8 MiB
        let mut buf: Vec<usize> = Vec::with_capacity(size);
        for i in 0..size {
            buf.push(i as usize);
        }
    } // Make sure we drop here.
    info!("large allocations work.");

    arch::debug::shutdown(ExitReason::Ok);
}

/// Checks that we can initialize ACPI, query the ACPI tables,
/// and parse the topology. The test ensures things work in case we
/// have no numa nodes.
#[cfg(all(feature = "integration-test", feature = "test-acpi-smoke"))]
pub fn xmain() {
    use topology::MACHINE_TOPOLOGY;

    // We have 2 cores ...
    assert_eq!(MACHINE_TOPOLOGY.num_threads(), 2);
    // ... no SMT ...
    assert_eq!(MACHINE_TOPOLOGY.num_cores(), 2);
    // ... 1 sockets ...
    assert_eq!(MACHINE_TOPOLOGY.num_packages(), 1);
    // ... no numa ...
    assert_eq!(MACHINE_TOPOLOGY.num_nodes(), 0);

    // ... and one IOAPIC which starts from GSI 0
    for (i, io_apic) in MACHINE_TOPOLOGY.io_apics().enumerate() {
        match i {
            0 => assert_eq!(io_apic.global_irq_base, 0, "GSI of I/O APIC is 0"),
            _ => assert_eq!(
                MACHINE_TOPOLOGY.io_apics().count(),
                1,
                "Found more than 1 IO APIC"
            ),
        };
    }

    arch::debug::shutdown(ExitReason::Ok);
}

/// Checks that we can initialize ACPI, query the ACPI tables
/// and correctly parse a large NUMA topology (8 sockets, 80 cores).
#[cfg(all(feature = "integration-test", feature = "test-acpi-topology"))]
pub fn xmain() {
    use topology::MACHINE_TOPOLOGY;

    // We have 80 cores ...
    assert_eq!(MACHINE_TOPOLOGY.num_threads(), 80);
    // ... no SMT ...
    assert_eq!(MACHINE_TOPOLOGY.num_cores(), 80);
    // ... 8 sockets ...
    assert_eq!(MACHINE_TOPOLOGY.num_packages(), 8);
    // ... on 8 numa-nodes ...
    assert_eq!(MACHINE_TOPOLOGY.num_nodes(), 8);

    // ... with 512 MiB of RAM per NUMA node ...
    for (nid, node) in MACHINE_TOPOLOGY.nodes().enumerate() {
        match nid {
            0 => assert_eq!(node.memory().count(), 2),
            _ => assert_eq!(node.memory().count(), 1),
        };

        let bytes_per_node: u64 = node.memory().map(|ma| ma.length).sum();

        if nid > 0 {
            assert_eq!(
                bytes_per_node,
                1024 * 1024 * 512,
                "Node#{} has 512 MiB of RAM",
                nid
            );
        } else {
            // First node has a bit less...
            assert!(
                bytes_per_node >= 1024 * 1024 * 511,
                "Node#0 has almost 512 MiB of RAM"
            );
        }
    }

    // ... and 10 cores per node ...
    for node in MACHINE_TOPOLOGY.nodes() {
        assert_eq!(node.cores().count(), 10);
    }

    // ... and 10 cores/threads per package ...
    for package in MACHINE_TOPOLOGY.packages() {
        assert_eq!(package.cores().count(), 10);
        assert_eq!(package.threads().count(), 10);
    }

    // ... and each core has 9 siblings ...
    for core in MACHINE_TOPOLOGY.cores() {
        assert_eq!(core.siblings().count(), 9);
    }

    // ... and one IOAPIC which starts from GSI 0
    for (i, io_apic) in MACHINE_TOPOLOGY.io_apics().enumerate() {
        match i {
            0 => assert_eq!(io_apic.global_irq_base, 0, "GSI of I/O APIC is 0"),
            _ => assert_eq!(
                MACHINE_TOPOLOGY.io_apics().count(),
                1,
                "Found more than 1 IO APIC"
            ),
        };
    }

    info!("test-acpi-topology done.");
    arch::debug::shutdown(ExitReason::Ok);
}

/// Tests core booting.
///
/// Boots a single core, checks we can print from it and arguments
/// get passed along correctly.
#[cfg(all(feature = "integration-test", feature = "test-coreboot-smoke"))]
pub fn xmain() {
    use crate::stack::{OwnedStack, Stack};
    use alloc::sync::Arc;
    use apic::ApicDriver;
    use arch::coreboot;
    use core::sync::atomic::{AtomicBool, Ordering};
    use topology;
    use x86::apic::ApicId;

    // Entry point for app. This function is called from start_ap.S:
    pub fn bespin_init_ap(arg1: Arc<u64>, initialized: &AtomicBool) {
        crate::arch::enable_sse();
        crate::arch::enable_fsgsbase();

        // Check that we can pass arguments:
        assert_eq!(*arg1, 0xfefe);
        assert_eq!(initialized.load(Ordering::SeqCst), false);

        // Don't change this string otherwise the test will fail:
        sprintln!("Hello from the other side");

        initialized.store(true, Ordering::SeqCst);
        assert_eq!(initialized.load(Ordering::SeqCst), true);
        loop {}
    }

    assert_eq!(topology::MACHINE_TOPOLOGY.num_threads(), 2, "No 2nd core?");

    let bsp_thread = topology::MACHINE_TOPOLOGY.current_thread();
    let thread_to_boot = topology::MACHINE_TOPOLOGY
        .threads()
        .find(|t| t != &bsp_thread)
        .expect("Didn't find an application core to boot...");

    unsafe {
        let initialized: AtomicBool = AtomicBool::new(false);
        let app_stack = OwnedStack::new(4096 * 32);

        let arg: Arc<u64> = Arc::new(0xfefe);
        coreboot::initialize(
            thread_to_boot.apic_id(),
            bespin_init_ap,
            Arc::clone(&arg),
            &initialized,
            &app_stack,
        );

        // Wait until core is up or we time out
        let timeout = x86::time::rdtsc() + 10_000_000;
        loop {
            // Did the core signal us initialization completed?
            if initialized.load(Ordering::SeqCst) {
                break;
            }

            // Have we waited long enough?
            if x86::time::rdtsc() > timeout {
                panic!("Core didn't boot properly...");
            }
        }

        assert!(initialized.load(Ordering::SeqCst));
        // Don't change this string otherwise the test will fail:
        info!("Core has started");
    }

    arch::debug::shutdown(ExitReason::Ok);
}

/// Tests booting of a core and using the node-replication
/// log to communicate information.
#[cfg(all(feature = "integration-test", feature = "test-coreboot-nrlog"))]
pub fn xmain() {
    use crate::stack::{OwnedStack, Stack};
    use apic::ApicDriver;
    use arch::coreboot;
    use core::sync::atomic::{AtomicBool, Ordering};
    use topology;
    use x86::apic::ApicId;

    use alloc::sync::Arc;
    use node_replication::log::Log;

    let mut log: Arc<Log<usize>> = Arc::new(Log::<usize>::new(1024 * 1024 * 1));

    // Entry point for app. This function is called from start_ap.S:
    pub fn bespin_init_ap(mylog: Arc<Log<usize>>, initialized: &AtomicBool) {
        crate::arch::enable_sse();
        crate::arch::enable_fsgsbase();

        mylog.append(&[0usize, 1usize], 1, |_o: usize, _i: usize| {});
        //assert!(r.is_some());

        // Don't change this string otherwise the test will fail:
        sprintln!("Hello from the other side");

        initialized.store(true, Ordering::SeqCst);
        loop {}
    }

    assert_eq!(topology::MACHINE_TOPOLOGY.num_threads(), 4, "Need 4 cores");

    let bsp_thread = topology::MACHINE_TOPOLOGY.current_thread();
    let thread = topology::MACHINE_TOPOLOGY
        .threads()
        .find(|t| t != &bsp_thread)
        .unwrap();

    unsafe {
        //for thread in threads_to_boot {
        let initialized: AtomicBool = AtomicBool::new(false);
        let app_stack = OwnedStack::new(4096 * 32);

        coreboot::initialize(
            thread.apic_id(),
            bespin_init_ap,
            log.clone(),
            &initialized,
            &app_stack,
        );

        // Wait until core is up or we time out
        let timeout = x86::time::rdtsc() + 10_000_000;
        loop {
            // Did the core signal us initialization completed?
            if initialized.load(Ordering::SeqCst) {
                break;
            }

            // Have we waited long enough?
            if x86::time::rdtsc() > timeout {
                panic!("Core didn't boot properly...");
            }
        }

        assert!(initialized.load(Ordering::SeqCst));
        // Don't change this string otherwise the test will fail:
        info!("Core has started");
    }

    arch::debug::shutdown(ExitReason::Ok);
}

/// Tests that the system initializes all cores.
#[cfg(all(feature = "integration-test", feature = "test-coreboot"))]
pub fn xmain() {
    // If we've come here the test has already completed,
    // as core initialization happens during init.
    arch::debug::shutdown(ExitReason::Ok);
}

/// Test process loading / user-space.
#[cfg(all(
    feature = "integration-test",
    any(feature = "test-userspace", feature = "test-userspace-smp")
))]
pub fn xmain() {
    // Ok -- this function is way too long because of several things that need to happen,
    // and they are currently (TODO) not neatly encapsulated away in modules/functions
    // We're loading a process from a module:
    // - First we are constructing our own custom elfloader trait to load figure out
    //   which program headers in the module will be writable (these should not be replicated by NR)
    // - Then we continue by creating a new Process through an nr call
    // - Then we allocate a bunch of memory on all NUMA nodes to create enough dispatchers
    //   so we can run on all cores
    // - Finally we allocate a dispatcher to the current core (0) and start running the process
    use alloc::sync::Arc;
    use alloc::vec::{self, Vec};
    use core::convert::TryInto;

    use crate::arch::memory::paddr_to_kernel_vaddr;
    use crate::arch::memory::LARGE_PAGE_SIZE;
    use crate::arch::process::Ring3Process;
    use crate::memory::KernelAllocator;
    use crate::memory::{Frame, PhysicalPageProvider, VAddr};
    use crate::prelude::overlaps;
    use crate::process::Executor;

    /// Our silly elfloader that is customized to only load the writeable
    /// sections of the program
    struct DataSecAllocator {
        offset: VAddr,
        frames: Vec<(usize, Frame)>,
        frame_copy_idx: usize,
    }

    impl DataSecAllocator {
        fn finish(self) -> Vec<Frame> {
            self.frames
                .into_iter()
                .map(|(_offset, base)| base)
                .collect()
        }
    }

    impl elfloader::ElfLoader for DataSecAllocator {
        fn allocate(
            &mut self,
            load_headers: elfloader::LoadableHeaders,
        ) -> Result<(), &'static str> {
            for header in load_headers.into_iter() {
                let base = header.virtual_addr();
                let size = header.mem_size() as usize;
                let flags = header.flags();

                // Calculate the offset and align to page boundaries
                // We can't expect to get something that is page-aligned from ELF
                let page_mask = (LARGE_PAGE_SIZE - 1) as u64;
                let page_base: VAddr = VAddr::from(base & !page_mask); // Round down to nearest page-size
                let size_page =
                    round_up!(size + (base & page_mask) as usize, LARGE_PAGE_SIZE as usize);
                assert!(size_page >= size);
                assert_eq!(size_page % LARGE_PAGE_SIZE, 0);
                assert_eq!(page_base % LARGE_PAGE_SIZE, 0);

                if flags.is_write() {
                    trace!(
                        "base = {:#x} size = {:#x} page_base = {:#x} size_page = {:#x}",
                        base,
                        size,
                        page_base,
                        size_page
                    );
                    let large_pages = size_page / LARGE_PAGE_SIZE;
                    KernelAllocator::try_refill_tcache(0, large_pages).expect("Refill didn't work");

                    let kcb = crate::kcb::get_kcb();
                    let mut pmanager = kcb.mem_manager();
                    for i in 0..large_pages {
                        let frame = pmanager
                            .allocate_large_page()
                            .expect("We refilled so allocation should work.");

                        trace!(
                            "add to self.frames  (elf_va={:#x}, pa={:#x})",
                            page_base.as_usize() + i * LARGE_PAGE_SIZE,
                            frame.base
                        );

                        self.frames
                            .push((page_base.as_usize() + i * LARGE_PAGE_SIZE, frame));
                    }
                }
            }
            Ok(())
        }

        fn load(
            &mut self,
            flags: elfloader::Flags,
            destination: u64,
            region: &[u8],
        ) -> Result<(), &'static str> {
            debug!(
                "load(): destination = {:#x} region.len() = {:#x}",
                destination,
                region.len(),
            );

            if flags.is_write() {
                let mut destination: usize = destination.try_into().unwrap();
                let mut region_remaining = region.len();
                let mut region = region;

                // Iterate over all frames to check which region(s) overlaps with it (so we'd need to copy)
                for (elf_begin, frame) in self.frames.iter() {
                    trace!(
                        "load(): into process vspace at {:#x} #bytes {:#x} offset_in_frame = {:#x}",
                        destination,
                        region.len(),
                        *elf_begin
                    );

                    // Compute range interval (in ELF space) for both the current frame
                    // and the region we want to copy into frames
                    let range_frame_elf = *elf_begin..*elf_begin + frame.size;
                    let range_region_elf = destination..destination + region_remaining;

                    if overlaps(&range_region_elf, &range_frame_elf) {
                        trace!(
                            "The frame overlaps with copy region (range_frame_elf={:x?} range_region_elf={:x?})",
                            range_frame_elf, range_region_elf
                        );

                        // Figure out which sub-slice of region goes into the frame
                        // i.e., compute the intersection of two ranges
                        let copy_start =
                            core::cmp::max(range_frame_elf.start, range_region_elf.start)
                                - destination;
                        let copy_end =
                            core::cmp::min(range_frame_elf.end, range_region_elf.end) - destination;
                        let region_to_copy = &region[copy_start..copy_end];
                        trace!("copy range = {:x?}", copy_start..copy_end);

                        // Figure out where `destination` is relative to the frame base
                        let copy_in_frame_start = destination - *elf_begin;
                        let frame_vaddr = paddr_to_kernel_vaddr(frame.base);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                region_to_copy.as_ptr(),
                                frame_vaddr.as_mut_ptr::<u8>().add(copy_in_frame_start),
                                copy_end - copy_start,
                            );
                            trace!(
                                "Copied {} bytes from {:p} to {:p}",
                                copy_end - copy_start,
                                region_to_copy.as_ptr(),
                                frame_vaddr.as_mut_ptr::<u8>().add(copy_start)
                            );

                            destination += copy_end - copy_start;
                            region = &region[copy_end..];
                            region_remaining -= copy_end - copy_start;
                        }
                    }
                }
            }

            Ok(())
        }

        fn relocate(
            &mut self,
            entry: &elfloader::Rela<elfloader::P64>,
        ) -> Result<(), &'static str> {
            // Get the pointer to where the relocation happens in the
            // memory where we loaded the headers
            // The forumla for this is our offset where the kernel is starting,
            // plus the offset of the entry to jump to the code piece
            let addr = self.offset + entry.get_offset();

            // Only relocate stuff in write-only frames that don't get replicated:
            for (pheader_offset, frame) in self.frames.iter() {
                let elf_vbase = self.offset + *pheader_offset & !(LARGE_PAGE_SIZE - 1);
                if addr >= elf_vbase && addr <= elf_vbase + frame.size() {
                    // Relocation is within this frame
                    let kernel_vaddr = paddr_to_kernel_vaddr(frame.base);
                    let offset_in_frame = addr - elf_vbase;

                    let kernel_addr = kernel_vaddr + offset_in_frame;
                    trace!(
                        "DataSecAllocator relocation paddr {:#x} kernel_addr {:#x}",
                        offset_in_frame + frame.base.as_u64(),
                        kernel_addr
                    );
                    use elfloader::TypeRela64;
                    if let TypeRela64::R_RELATIVE = TypeRela64::from(entry.get_type()) {
                        // This is a relative relocation of a 64 bit value, we add the offset (where we put our
                        // binary in the vspace) to the addend and we're done:
                        unsafe {
                            // Scary unsafe changing stuff in random memory locations based on
                            // ELF binary values weee!
                            *(kernel_addr.as_mut_ptr::<u64>()) =
                                self.offset.as_u64() + entry.get_addend();
                        }
                    } else {
                        return Err("Can only handle R_RELATIVE for relocation");
                    }
                }
            }

            Ok(())
        }
    }

    // Load the process (parse ELF, create VSpace etc.)
    KernelAllocator::try_refill_tcache(7, 1).expect("Can't reserve memory for ELF data section");
    let pid = {
        let kcb = kcb::get_kcb();

        // Lookup binary name we want to load for the test
        let mut test_module = None;
        for module in &kcb.arch.kernel_args().modules {
            if module.name() == kcb.cmdline.test_binary {
                test_module = Some(module);
            }
        }

        use alloc::format;
        let test_module = test_module
            .expect(format!("Couldn't find '{}' binary.", kcb.cmdline.test_binary).as_str());
        info!("{} {:?}", kcb.cmdline.test_binary, test_module);

        let module = unsafe {
            elfloader::ElfBinary::new(test_module.name(), test_module.as_slice())
                .expect("Module is not a valid ELF binary")
        };

        // We don't have an offset for non-pie applications (rump apps)
        let offset = if !module.is_pie() {
            VAddr::zero()
        } else {
            VAddr::from(0x20_0000_0000usize)
        };

        let mut data_sec_loader = DataSecAllocator {
            offset,
            frames: Vec::with_capacity(2),
            frame_copy_idx: 0,
        };
        module.load(&mut data_sec_loader);
        let data_frames: Vec<Frame> = data_sec_loader.finish();

        // Create a new process
        let replica = kcb.arch.replica.as_ref().expect("Replica not set");
        let response = replica.execute(
            nr::Op::ProcCreate(&test_module, data_frames),
            kcb.arch.replica_idx,
        );
        let pid = match response {
            Ok(nr::NodeResult::ProcCreated(pid)) => pid,
            _ => unreachable!("Got unexpected response"),
        };
        pid
    };

    // Register a periodic timer to advance replica
    {
        use apic::ApicDriver;
        let kcb = crate::kcb::get_kcb();
        let mut apic = kcb.arch.apic();
        apic.tsc_enable();
        unsafe { apic.tsc_set(x86::time::rdtsc() + arch::irq::TSC_TIMER_DEADLINE) };
    }

    // Create enough dispatchers to run on all cores:
    // (Also make sure they're all NUMA local)
    info!("Allocate dispatchers");
    {
        let mut create_per_region: Vec<(topology::NodeId, usize)> =
            Vec::with_capacity(topology::MACHINE_TOPOLOGY.num_nodes() + 1);
        if topology::MACHINE_TOPOLOGY.num_nodes() > 0 {
            for node in topology::MACHINE_TOPOLOGY.nodes() {
                let threads = node.threads().count();
                create_per_region.push((node.id, threads));
            }
        } else {
            create_per_region.push((0, topology::MACHINE_TOPOLOGY.num_threads()));
        }

        for (affinity, to_create) in create_per_region {
            let mut dispatchers_created = 0;
            while dispatchers_created < to_create {
                KernelAllocator::try_refill_tcache(20, 1).expect("Refill didn't work");
                let frame = {
                    let kcb = crate::kcb::get_kcb();
                    kcb.physical_memory.gmanager.unwrap().node_caches[affinity as usize]
                        .lock()
                        .allocate_large_page()
                        .expect("Can't allocate lp")
                };

                let kcb = crate::kcb::get_kcb();
                let replica = kcb.arch.replica.as_ref().expect("Replica not set");
                let response = replica.execute(
                    nr::Op::DispatcherAllocation(pid, frame),
                    kcb.arch.replica_idx,
                );
                match response {
                    Ok(nr::NodeResult::ExecutorsCreated(how_many)) => {
                        assert!(how_many > 0);
                        dispatchers_created += how_many;
                    }
                    _ => unreachable!("Got unexpected response"),
                };
            }
        }
    }
    info!("Allocated dispatchers");

    let thread = topology::MACHINE_TOPOLOGY.current_thread();
    // Set current thread to run executor from our process
    let (gtid, eid) = {
        nr::KernelNode::<Ring3Process>::allocate_core_to_process(
            pid,
            VAddr::from(0xdeadbfffu64),
            thread.node_id.or(Some(0)),
            Some(thread.id),
        )
        .expect("Can't allocate core")
    };

    let kcb = kcb::get_kcb();
    let replica = kcb.arch.replica.as_ref().expect("Replica not set");

    // Get an executor
    let response = replica.execute_ro(
        nr::ReadOps::CurrentExecutor(thread.id),
        kcb.arch.replica_idx,
    );
    let executor = match response {
        Ok(nr::NodeResult::Executor(e)) => e,
        e => unreachable!("Got unexpected response {:?}", e),
    };

    info!("Created the init process, about to go there...");
    use alloc::sync::Weak;
    let no = kcb::get_kcb()
        .arch
        .swap_current_process(Weak::upgrade(&executor).unwrap());
    assert!(no.is_none());

    unsafe {
        let rh = kcb::get_kcb().arch.current_process().map(|p| p.start());
        rh.unwrap().resume();
    }
}

/// Test SSE/floating point in the kernel.
#[cfg(all(feature = "integration-test", feature = "test-sse"))]
pub fn xmain() {
    info!("division = {}", 10.0 / 2.19);
    info!("division by zero = {}", 10.0 / 0.0);
    arch::debug::shutdown(ExitReason::Ok);
}

/// Test VSpace debugging.
#[cfg(all(feature = "integration-test", feature = "test-vspace-debug"))]
pub fn xmain() {
    use core::borrow::Borrow;
    use graphviz::*;

    let kcb = kcb::get_kcb();
    graphviz::render_opts(&*kcb.arch.init_vspace(), &[RenderOption::RankDirectionLR]);

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(
    feature = "integration-test",
    any(
        feature = "test-pfault-early",
        feature = "test-gpfault-early",
        feature = "test-double-fault"
    )
))]
pub fn xmain() {
    arch::debug::shutdown(ExitReason::ReturnFromMain);
}
