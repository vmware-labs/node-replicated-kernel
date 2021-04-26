// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

/// Test wrgsbase performance.
#[cfg(all(feature = "integration-test", feature = "test-wrgsbase"))]
pub fn xmain() {
    unsafe {
        let iterations = 100_000;
        let start = x86::time::rdtsc();
        for i in 0..iterations {
            x86::current::segmentation::wrgsbase(0x1);
        }
        let end = x86::time::rdtsc();
        info!("wrgsbase cycles: {}", (end - start) / iterations)
    }
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
    use atopology::MACHINE_TOPOLOGY;

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
    use atopology::MACHINE_TOPOLOGY;

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
    use atopology;
    use core::sync::atomic::{AtomicBool, Ordering};
    use x86::apic::ApicId;

    // Entry point for app. This function is called from start_ap.S:
    pub fn nrk_init_ap(arg1: Arc<u64>, initialized: &AtomicBool) {
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

    assert_eq!(atopology::MACHINE_TOPOLOGY.num_threads(), 2, "No 2nd core?");

    let bsp_thread = atopology::MACHINE_TOPOLOGY.current_thread();
    let thread_to_boot = atopology::MACHINE_TOPOLOGY
        .threads()
        .find(|t| t != &bsp_thread)
        .expect("Didn't find an application core to boot...");

    unsafe {
        let initialized: AtomicBool = AtomicBool::new(false);
        let app_stack = OwnedStack::new(4096 * 32);

        let arg: Arc<u64> = Arc::new(0xfefe);
        coreboot::initialize(
            thread_to_boot.apic_id(),
            nrk_init_ap,
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
    use atopology;
    use core::sync::atomic::{AtomicBool, Ordering};
    use x86::apic::ApicId;

    use alloc::sync::Arc;
    use node_replication::Log;

    let mut log: Arc<Log<usize>> = Arc::new(Log::<usize>::new(1024 * 1024 * 1));

    // Entry point for app. This function is called from start_ap.S:
    pub fn nrk_init_ap(mylog: Arc<Log<usize>>, initialized: &AtomicBool) {
        crate::arch::enable_sse();
        crate::arch::enable_fsgsbase();

        mylog.append(&[0usize, 1usize], 1, |_o: usize, _i: usize| {});
        //assert!(r.is_some());

        // Don't change this string otherwise the test will fail:
        sprintln!("Hello from the other side");

        initialized.store(true, Ordering::SeqCst);
        loop {}
    }

    assert_eq!(atopology::MACHINE_TOPOLOGY.num_threads(), 4, "Need 4 cores");

    let bsp_thread = atopology::MACHINE_TOPOLOGY.current_thread();
    let thread = atopology::MACHINE_TOPOLOGY
        .threads()
        .find(|t| t != &bsp_thread)
        .unwrap();

    unsafe {
        //for thread in threads_to_boot {
        let initialized: AtomicBool = AtomicBool::new(false);
        let app_stack = OwnedStack::new(4096 * 32);

        coreboot::initialize(
            thread.apic_id(),
            nrk_init_ap,
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
    let kcb = kcb::get_kcb();
    crate::arch::process::spawn(kcb.cmdline.init_binary);
    crate::scheduler::schedule()
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

/// Test shootdown facilities in the kernel.
#[cfg(all(
    feature = "integration-test",
    feature = "test-replica-advance",
    target_arch = "x86_64"
))]
pub fn xmain() {
    use alloc::sync::Arc;
    use arch::tlb::advance_replica;
    let threads = atopology::MACHINE_TOPOLOGY.num_threads();

    unsafe {
        let start = rawtime::Instant::now();
        advance_replica(0x1, 0x0);
        let duration = start.elapsed().as_nanos();

        info!("advance-replica done?");
        loop {}
    }
    arch::debug::shutdown(ExitReason::Ok);
}

/// Test vmxnet3 in the kernel.
#[cfg(all(
    feature = "integration-test",
    feature = "test-vmxnet",
    target_arch = "x86_64"
))]
pub fn xmain() {
    use alloc::alloc::Layout;
    use alloc::prelude::v1::*;
    use alloc::vec;

    use crate::memory::vspace::MapAction;
    use crate::memory::PAddr;

    use driverkit::devq::*;
    use driverkit::iomem::*;

    let kcb = crate::kcb::get_kcb();
    // TODO(hack): Map vmxnet3 bars
    // BAR0: 0x81828000
    kcb.arch.init_vspace().map_identity(
        PAddr::from(0x81828000u64),
        0x1000,
        MapAction::ReadWriteKernel,
    );
    // BAR1: 0x81827000
    kcb.arch.init_vspace().map_identity(
        PAddr::from(0x81827000u64),
        0x1000,
        MapAction::ReadWriteKernel,
    );

    info!(
        "vmxnet3 size {}",
        core::mem::size_of::<vmxnet3::vmx::VMXNet3>()
    );
    arch::irq::enable();
    let mut vmx = vmxnet3::vmx::VMXNet3::new(2, 2, 128, 128).unwrap();
    vmx.attach_pre();
    vmx.init();

    let mut bufchain = IOBufChain::new(0, 0, 0, 1).expect("Can't make IoBufChain?");
    let mut packet = IOBuf::new(Layout::from_size_align(1024, 128).expect("Correct Layout"))
        .expect("Can't malke packet?");
    /*
    000000: 00 A0 CC 63 08 1B 00 40 : 95 49 03 5F 08 00 45 00 ...c...@.I._..E.
    000010: 00 3C 82 47 00 00 20 01 : 94 C9 C0 A8 01 20 C0 A8 .<.G.. ...... ..
    000020: 01 40 08 00 48 5C 01 00 : 04 00 61 62 63 64 65 66 .@..H\....abcdef
    000030: 67 68 69 6A 6B 6C 6D 6E : 6F 70 71 72 73 74 75 76 ghijklmnopqrstuv
    000040: 77 61 62 63 64 65 66 67 : 68 69                   wabcdefghi......
    */
    let raw_data = vec![
        //56:b4:44:e9:62:dc
        0x00, 0xA0, 0xCC, 0x63, 0x08, 0x1B, 0x56, 0xb4, 044, 0xe9, 0x62, 0xdc, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x3C, 0x82, 0x47, 0x00, 0x00, 0x20, 0x01, 0x94, 0xC9, 0xC0, 0xA8, 0x01, 0x20,
        0xC0, 0xA8, 0x01, 0x40, 0x08, 0x00, 0x48, 0x5C, 0x01, 0x00, 0x04, 0x00, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
        0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    ];
    packet.copy_in(raw_data.as_slice());
    bufchain.segments.push_back(packet);
    vmx.enqueue(bufchain).expect("Enq failed");
    vmx.flush(0, 1).expect("Flush failed?");
    loop {
        unsafe { x86::halt() };
    }

    arch::debug::shutdown(ExitReason::Ok);
}

/// Test shootdown facilities in the kernel.
#[cfg(all(
    feature = "integration-test",
    feature = "test-shootdown-simple",
    target_arch = "x86_64"
))]
pub fn xmain() {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use apic::ApicDriver;
    use core::sync::atomic::spin_loop_hint;
    use core::time::Duration;
    use x86::apic::{
        ApicId, DeliveryMode, DeliveryStatus, DestinationMode, DestinationShorthand, Icr, Level,
        TriggerMode,
    };

    let threads = atopology::MACHINE_TOPOLOGY.num_threads();

    unsafe {
        let start = rawtime::Instant::now();

        let mut shootdowns = Vec::with_capacity(threads);
        for t in atopology::MACHINE_TOPOLOGY.threads() {
            let id = t.apic_id();
            info!(
                "{:?} logical {:?} cluster {:?} cluster rel. logical {:?}",
                id,
                id.x2apic_logical_id(),
                id.x2apic_logical_cluster_id(),
                id.x2apic_logical_cluster_address(),
            );
            let shootdown = Arc::new(arch::tlb::Shootdown::new(0x1000..0x2000));
            arch::tlb::enqueue(t.id, arch::tlb::WorkItem::Shootdown(shootdown.clone()));
            shootdowns.push(shootdown);
        }

        {
            let kcb = crate::kcb::get_kcb();
            let mut apic = kcb.arch.apic();

            let vector = 251;
            let icr = Icr::for_x2apic(
                vector,
                ApicId::X2Apic(0b1_1111_1111_1111_1111),
                DestinationShorthand::NoShorthand,
                DeliveryMode::Fixed,
                DestinationMode::Logical,
                DeliveryStatus::Idle,
                Level::Assert,
                TriggerMode::Edge,
            );

            apic.send_ipi(icr)
        }

        for shootdown in shootdowns {
            if !shootdown.is_acknowledged() {
                spin_loop_hint();
            }
        }
        let duration = start.elapsed().as_nanos();

        info!("name,cores,shootdown_duration_ns");
        info!("shootdown-simple,{},{}", threads, duration);
    }
    arch::debug::shutdown(ExitReason::Ok);
}
