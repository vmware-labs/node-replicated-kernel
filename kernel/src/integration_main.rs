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

#[cfg(all(feature = "integration-test", feature = "test-buddy"))]
pub fn xmain() {
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

#[cfg(all(feature = "integration-test", feature = "test-exit"))]
pub fn xmain() {
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-test", feature = "test-pfault"))]
#[inline(never)]
pub fn xmain() {
    use arch::memory::{paddr_to_kernel_vaddr, PAddr};

    unsafe {
        let paddr = PAddr::from(0xdeadbeefu64);
        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);
        let ptr: *mut u64 = kernel_vaddr.as_mut_ptr();
        debug!("before causing the pfault");
        let val = *ptr;
        assert!(val != 0);
    }
}

#[cfg(all(feature = "integration-test", feature = "test-gpfault"))]
pub fn xmain() {
    // Note that int!(13) doesn't work in qemu. It doesn't push an error code properly for it.
    // So we cause a GP by loading garbage in the ss segment register.
    use x86::segmentation::{load_ss, SegmentSelector};
    unsafe {
        load_ss(SegmentSelector::new(99, x86::Ring::Ring3));
    }
}

#[cfg(all(feature = "integration-test", feature = "test-alloc"))]
pub fn xmain() {
    use alloc::vec::Vec;
    {
        let mut buf: Vec<u8> = Vec::with_capacity(0);
        for i in 0..1024 {
            buf.push(i as u8);
        }
    } // Make sure we drop here.
    info!("small allocations work.");

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
    info!("large allocations work.");
    arch::debug::shutdown(ExitReason::Ok);
}

/// Checks that we can initialize ACPI and query the ACPI tables.
///
/// # Note
/// This test is supposed to spawn on a topology with 2 sockets, 1 core each
/// 2 numa nodes (one per socket) with 512 MiB RAM each.
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

/// Checks that we can initialize ACPI and query the ACPI tables.
///
/// # Note
/// This test is supposed to spawn on a topology with 2 sockets, 1 core each
/// 2 numa nodes (one per socket) with 512 MiB RAM each.
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

    // ... and each core has 10 siblings ...
    for core in MACHINE_TOPOLOGY.cores() {
        assert_eq!(core.siblings().count(), 10);
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

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-test", feature = "test-coreboot-smoke"))]
static mut COREBOOT_STACK: [u8; 4096 * 32] = [0; 4096 * 32];

#[cfg(all(feature = "integration-test", feature = "test-coreboot-smoke"))]
pub fn xmain() {
    use arch::memory::{PAddr, BASE_PAGE_SIZE};
    use arch::vspace::MapAction;
    use topology;

    use x86::apic::{ApicControl, ApicId};

    let kcb = crate::arch::kcb::get_kcb();
    const X86_64_REAL_MODE_SEGMENT: u16 = 0x0600;
    let real_mode_page = X86_64_REAL_MODE_SEGMENT >> 8;
    let real_mode_linear_offset = X86_64_REAL_MODE_SEGMENT << 4;

    extern "C" {
        static x86_64_start_ap: *const u8;
        static x86_64_start_ap_end: *const u8;
        static x86_64_init_ap_absolute_entry: *mut extern "C" fn();
        static x86_64_init_ap_init_pml4: *mut extern "C" fn();
        static start_ap_stack_ptr: *mut extern "C" fn();
    };
    let _boot_code_size = unsafe { (x86_64_start_ap).offset_from(x86_64_start_ap_end) as usize };

    //acpi::process_pcie();

    assert_eq!(topology::MACHINE_TOPOLOGY.num_threads(), 2, "Found a core");

    unsafe {
        let start_addr: usize = core::mem::transmute(&x86_64_start_ap);
        let end_addr: usize = core::mem::transmute(&x86_64_start_ap_end);
        let boot_code_size = end_addr - start_addr;
        info!("boot_code_size = {:#x}", boot_code_size);

        let real_mode_base: usize = 0x0 + real_mode_linear_offset as usize;
        info!("real_mode_base = {:#x}", real_mode_base);
        let ap_bootstrap_code: &'static [u8] =
            core::slice::from_raw_parts(&x86_64_start_ap as *const _ as *const u8, boot_code_size);
        let real_mode_destination: &mut [u8] =
            core::slice::from_raw_parts_mut(real_mode_base as *mut u8, boot_code_size);

        kcb.init_vspace().map_identity(
            PAddr::from(real_mode_base as u64),
            PAddr::from((real_mode_base + 20 * BASE_PAGE_SIZE) as u64),
            MapAction::ReadWriteExecuteKernel,
        );

        let entry_pointer: *mut u64 = core::mem::transmute(&x86_64_init_ap_absolute_entry);
        *entry_pointer = crate::arch::bespin_init_ap as u64;
        info!(
            "crate::arch::bespin_init_ap = {:#x}",
            crate::arch::bespin_init_ap as u64
        );

        real_mode_destination.copy_from_slice(ap_bootstrap_code);
        let entry_pointer: *mut u64 = core::mem::transmute(
            &x86_64_init_ap_absolute_entry as *const _ as u64 - start_addr as u64
                + real_mode_base as u64,
        );
        *entry_pointer = crate::arch::bespin_init_ap as u64;

        let pml4_pointer: *mut u64 = core::mem::transmute(
            &x86_64_init_ap_init_pml4 as *const _ as u64 - start_addr as u64
                + real_mode_base as u64,
        );
        *pml4_pointer = kcb.init_vspace().pml4_address().into();

        let stack_pointer: *mut u64 = core::mem::transmute(
            &start_ap_stack_ptr as *const _ as u64 - start_addr as u64 + real_mode_base as u64,
        );
        *stack_pointer = &COREBOOT_STACK as *const _ as u64 + 32 * 4096 - 16;

        info!("start_addr: {:#x}", start_addr);
        info!(
            "x86_64_start_ap = {:p} {:#x}",
            entry_pointer, *entry_pointer
        );
        info!("pml4_pointer = {:p} {:#x}", pml4_pointer, *pml4_pointer);
        info!("pml4 on bsp: {:#x}", kcb.init_vspace().pml4_address());

        // Have fun launching some cores:
        kcb.apic().ipi_init(ApicId::XApic(1));
        kcb.apic().ipi_init_deassert();

        kcb.apic()
            .ipi_startup(ApicId::XApic(1), real_mode_page as u8);

        // Wait for a while
        let break_time = x86::time::rdtsc() + 1000000;
        loop {
            if x86::time::rdtsc() > break_time {
                break;
            }
        }
        info!("Cores should've started?");
    }

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-test", feature = "test-scheduler"))]
pub fn xmain() {
    let cpuid = x86::cpuid::CpuId::new();
    assert!(
        cpuid
            .get_extended_feature_info()
            .map_or(false, |ef| ef.has_fsgsbase()),
        "FS/GS base instructions supported"
    );
    use lineup::tls::Environment;

    let mut s = lineup::Scheduler::new(lineup::DEFAULT_UPCALLS);
    s.spawn(
        4096,
        |arg| {
            let _r = Environment::thread().relinquish();
            info!("lwt1 {:?}", Environment::tid());
        },
        core::ptr::null_mut(),
    );

    s.spawn(
        4096,
        |arg| {
            info!("lwt2 {:?}", Environment::tid());
        },
        core::ptr::null_mut(),
    );

    s.run();
    s.run();
    s.run();
    s.run();

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-test", feature = "test-userspace"))]
pub fn xmain() {
    let init_module = kcb::try_get_kcb()
        .map(|kcb| kcb.kernel_args().modules[1].clone())
        .expect("Need to have an init module.");

    trace!("init {:?}", init_module);
    let mut process = alloc::boxed::Box::new(
        arch::process::Process::from(init_module).expect("Couldn't load init."),
    );

    info!("Created the init process, about to go there...");
    let no = kcb::get_kcb().swap_current_process(process);
    assert!(no.is_none());

    unsafe {
        let rh = kcb::get_kcb().current_process().as_mut().map(|p| p.start());
        rh.unwrap().resume();
    }

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-test", feature = "test-sse"))]
pub fn xmain() {
    info!("division = {}", 10.0 / 2.19);
    info!("division by zero = {}", 10.0 / 0.0);
    arch::debug::shutdown(ExitReason::Ok);
}
