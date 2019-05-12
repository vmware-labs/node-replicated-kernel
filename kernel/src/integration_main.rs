#[cfg(all(feature = "integration-tests", feature = "test-time"))]
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

#[cfg(all(feature = "integration-tests", feature = "test-rump-tmpfs"))]
pub fn xmain() {
    use cstr_core::CStr;

    #[repr(C)]
    struct tmpfs_args {
        ta_version: u64, // c_int
        /* Size counters. */
        ta_nodes_max: u64, // ino_t			ta_nodes_max;
        ta_size_max: i64,  // off_t			ta_size_max;
        /* Root node attributes. */
        ta_root_uid: u32,  // uid_t			ta_root_uid;
        ta_root_gid: u32,  // gid_t			ta_root_gid;
        ta_root_mode: u32, // mode_t			ta_root_mode;
    }

    extern "C" {
        fn rump_boot_setsigmodel(sig: usize);
        fn rump_init() -> u64;
        fn mount(typ: *const i8, path: *const i8, n: u64, args: *const tmpfs_args, argsize: usize);
        fn open(path: *const i8, opt: u64) -> i64;
        fn read(fd: i64, buf: *mut i8, bytes: u64) -> i64;
        fn write(fd: i64, buf: *const i8, bytes: u64) -> i64;
    }

    let up = lineup::Upcalls {
        curlwp: rumprt::rumpkern_curlwp,
        deschedule: rumprt::rumpkern_unsched,
        schedule: rumprt::rumpkern_sched,
    };

    let mut scheduler = lineup::Scheduler::new(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(0);
            let ri = rump_init();
            assert_eq!(ri, 0);

            let TMPFS_ARGS_VERSION: u64 = 1;

            let tfsa = tmpfs_args {
                ta_version: TMPFS_ARGS_VERSION,
                ta_nodes_max: 0,
                ta_size_max: 1 * 1024 * 1024,
                ta_root_uid: 0,
                ta_root_gid: 0,
                ta_root_mode: 0o1777,
            };

            let path = CStr::from_bytes_with_nul(b"/tmp\0");
            let MOUNT_TMPFS = CStr::from_bytes_with_nul(b"tmpfs\0");
            info!("mounting tmpfs");

            let r = mount(
                MOUNT_TMPFS.unwrap().as_ptr(),
                path.unwrap().as_ptr(),
                0,
                &tfsa,
                core::mem::size_of::<tmpfs_args>(),
            );

            let path = CStr::from_bytes_with_nul(b"/tmp/bla\0");
            let fd = open(path.unwrap().as_ptr(), 0x00000202);
            assert_eq!(fd, 3, "Proper FD was returned");

            let wbuf: [i8; 12] = [0xa; 12];
            let bytes_written = write(fd, wbuf.as_ptr(), 12);
            assert_eq!(bytes_written, 12, "Write successful");
            info!("bytes_written: {:?}", bytes_written);

            let path = CStr::from_bytes_with_nul(b"/tmp/bla\0");
            let fd = open(path.unwrap().as_ptr(), 0x00000002);
            let mut rbuf: [i8; 12] = [0x00; 12];
            let read_bytes = read(fd, rbuf.as_mut_ptr(), 12);
            assert_eq!(read_bytes, 12, "Read successful");
            assert_eq!(rbuf[0], 0xa, "Read matches write");
            info!("bytes_read: {:?}", read_bytes);

            arch::debug::shutdown(ExitReason::Ok);
        },
        core::ptr::null_mut(),
    );

    loop {
        scheduler.run();
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-rump-net"))]
pub fn xmain() {
    use cstr_core::CStr;

    #[repr(C)]
    struct sockaddr_in {
        sin_len: u8,
        sin_family: u8, //typedef __uint8_t       __sa_family_t;
        sin_port: u16,  // typedef __uint16_t      __in_port_t;    /* "Internet" port number */
        sin_addr: u32,  // typedef __uint32_t      __in_addr_t;    /* IP(v4) address */
        zero: [u8; 8],
    }

    extern "C" {
        fn rump_boot_setsigmodel(sig: usize);
        fn rump_init() -> u64;
        fn rump_pub_netconfig_dhcp_ipv4_oneshot(iface: *const i8) -> i64;

        fn socket(domain: i64, typ: i64, protocol: i64) -> i64;
        fn rump___sysimpl_sendto(
            fd: i64,
            buf: *const i8,
            flags: i64,
            len: usize,
            addr: *const sockaddr_in,
            len: usize,
        ) -> i64;
        fn close(sock: i64) -> i64;
    }

    let up = lineup::Upcalls {
        curlwp: rumprt::rumpkern_curlwp,
        deschedule: rumprt::rumpkern_unsched,
        schedule: rumprt::rumpkern_sched,
    };

    let mut scheduler = lineup::Scheduler::new(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(1);
            let ri = rump_init();
            assert_eq!(ri, 0);
            info!("rump_init({}) done in {:?}", ri, start.elapsed());

            let iface = CStr::from_bytes_with_nul(b"wm0\0");
            let r = rump_pub_netconfig_dhcp_ipv4_oneshot(iface.unwrap().as_ptr());
            assert_eq!(r, 0, "rump_pub_netconfig_dhcp_ipv4_oneshot");

            let AF_INET = 2;
            let SOCK_DGRAM = 2;

            let sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            assert!(sockfd > 0);

            let addr = sockaddr_in {
                sin_len: core::mem::size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: (8889 as u16).to_be(),
                sin_addr: (2887712788 as u32).to_be(), // 172.31.0.20
                zero: [0; 8],
            };

            for i in 0..5 {
                info!("sendto msg = {}", i);

                use alloc::format;
                let buf = format!("pkt {}\n\0", i);
                let cstr = CStr::from_bytes_with_nul(buf.as_str().as_bytes()).unwrap();
                core::mem::forget(cstr);

                let r = rump___sysimpl_sendto(
                    sockfd,
                    cstr.as_ptr() as *const i8,
                    buf.len() as i64,
                    0,
                    &addr as *const sockaddr_in,
                    core::mem::size_of::<sockaddr_in>(),
                );
                assert_eq!(r, buf.len() as i64);
                let _r = lineup::tls::Environment::thread().relinquish();
            }

            let r = close(sockfd);
            assert_eq!(r, 0);
        },
        core::ptr::null_mut(),
    );

    scheduler
        .spawn(
            32 * 1024,
            |_yielder| unsafe {
                rumprt::dev::irq_handler(core::ptr::null_mut());
                unreachable!("should not exit");
            },
            core::ptr::null_mut(),
        )
        .expect("Can't create IRQ thread?");

    loop {
        scheduler.run();
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-buddy"))]
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

#[cfg(all(feature = "integration-tests", feature = "test-exit"))]
pub fn xmain() {
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-pfault"))]
#[inline(never)]
pub fn xmain() {
    use arch::memory::{paddr_to_kernel_vaddr, PAddr};

    unsafe {
        let paddr = PAddr::from(0xdeadbeef);
        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);
        let ptr: *mut u64 = kernel_vaddr.as_mut_ptr();
        debug!("before causing the pfault");
        let val = *ptr;
        assert!(val != 0);
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-gpfault"))]
pub fn xmain() {
    // Note that int!(13) doesn't work in qemu. It doesn't push an error code properly for it.
    // So we cause a GP by loading garbage in the ss segment register.
    use x86::segmentation::{load_ss, SegmentSelector};
    unsafe {
        load_ss(SegmentSelector::new(99, x86::Ring::Ring3));
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-alloc"))]
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

#[cfg(all(feature = "integration-tests", feature = "test-acpi"))]
pub fn xmain() {
    use arch::acpi;

    let mut scheduler = lineup::Scheduler::new(lineup::DEFAULT_UPCALLS);
    scheduler.spawn(
        32 * 4096,
        |_| {
            let r = acpi::init();
            assert!(r.is_ok());
            info!("acpi initialized");


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

#[cfg(all(feature = "integration-tests", feature = "test-scheduler"))]
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

#[cfg(all(feature = "integration-tests", feature = "test-sse"))]
pub fn xmain() {
    info!("division = {}", 10.0 / 2.19);
    info!("division by zero = {}", 10.0 / 0.0);
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-linux"))]
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
