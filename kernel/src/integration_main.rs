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

#[cfg(all(feature = "integration-test", feature = "test-acpi"))]
pub fn xmain() {
    use arch::acpi;

    let mut scheduler = lineup::Scheduler::new(lineup::DEFAULT_UPCALLS);
    scheduler.spawn(
        32 * 4096,
        |_| {
            const X86_64_REAL_MODE_SEGMENT: u16 = 0x0600;
            let real_mode_page = X86_64_REAL_MODE_SEGMENT >> 8;
            let real_mode_linear_offset = X86_64_REAL_MODE_SEGMENT << 4;

            extern "C" {
                static x86_64_start_ap: *const u8;
                static x86_64_start_ap_end: *const u8;
                static x86_64_init_ap_absolute_entry: *mut fn();
            };
            let boot_code_size =
                unsafe { (x86_64_start_ap).offset_from(x86_64_start_ap_end) as usize };

            acpi::process_pcie();

            assert_eq!(acpi::LOCAL_APICS.len(), 1, "Found a core");
            assert_eq!(acpi::IO_APICS.len(), 1, "Found an IO APIC");

            /*unsafe {
                let start_addr: usize = core::mem::transmute(&x86_64_start_ap);
                let end_addr: usize = core::mem::transmute(&x86_64_start_ap_end);
                let boot_code_size = end_addr - start_addr;
                info!("boot_code_size = {:#x}", boot_code_size);

                let real_mode_base: usize = 0x0 + real_mode_linear_offset as usize;
                info!("real_mode_base = {:#x}", real_mode_base);
                let ap_bootstrap_code: &'static [u8] = unsafe {
                    core::slice::from_raw_parts(
                        &x86_64_start_ap as *const _ as *const u8,
                        boot_code_size,
                    )
                };
                let real_mode_destination: &mut [u8] = unsafe {
                    core::slice::from_raw_parts_mut(real_mode_base as *mut u8, boot_code_size)
                };

                let entry_pointer: *mut u64 = core::mem::transmute(&x86_64_init_ap_absolute_entry);
                *entry_pointer = bespin_init_ap as u64;

                vspace.map_identity(
                    VAddr::from(real_mode_base),
                    VAddr::from(real_mode_base) + 20 * BASE_PAGE_SIZE,
                );

                real_mode_destination.copy_from_slice(ap_bootstrap_code);

                info!("x86_64_start_ap = {:p} {:#x}", &x86_64_start_ap, start_addr);
                info!(
                    "x86_64_start_ap = {:p} {:#x}",
                    &x86_64_start_ap_end, end_addr
                );

                // Have fun launching some cores:
                apic.ipi_init();
                apic.ipi_init_deassert();

                apic.ipi_startup(real_mode_page as u8);
                info!("Cores should've started?");
            }*/

            arch::debug::shutdown(ExitReason::Ok);
        },
        core::ptr::null_mut(),
    );

    loop {
        scheduler.run();
    }
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

#[cfg(all(feature = "integration-test", feature = "test-linux"))]
pub fn xmain() {
    use cstr_core::CStr;

    extern "C" {
        // int __init lkl_start_kernel(struct lkl_host_operations *ops, const char *fmt, ...)
        fn lkl_start_kernel(ops: *const lkl::lkl_host_operations, fmt: *const i8) -> i32;
        fn lkl_sys_halt();
    }

    let up = lineup::DEFAULT_UPCALLS;

    let mut scheduler = lineup::Scheduler::new(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let linux_ops = linuxrt::get_host_ops();
            let boot_arg = CStr::from_bytes_with_nul(b"mem=16M loglevel=8\0");
            let r = lkl_start_kernel(&linux_ops, boot_arg.unwrap().as_ptr());
            info!("lkl_start_kernel {}", r);

            arch::debug::shutdown(ExitReason::Ok);
        },
        core::ptr::null_mut(),
    );

    loop {
        scheduler.run();
    }
}
