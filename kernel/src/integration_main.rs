#[cfg(all(feature = "integration-tests", feature = "test-time"))]
pub fn main() {
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

#[cfg(all(feature = "integration-tests", feature = "test-rump-tmpfs"))]
pub fn main() {
    use cstr_core::CStr;

    extern "C" {
        fn rump_boot_setsigmodel(sig: usize);
        fn rump_init() -> u64;
        fn mount(typ: *const i8, path: *const i8, n: u64, args: *const tmpfs_args, argsize: usize);
        fn rump_component_count(fac: u64) -> u64;
        fn open(path: *const i8, opt: u64) -> i64;
        fn read(fd: i64, buf: *mut i8, bytes: u64) -> i64;
        fn write(fd: i64, buf: *const i8, bytes: u64) -> i64;
        fn rump_pub_netconfig_dhcp_ipv4_oneshot(iface: *const i8) -> i64;
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
            info!("rump___sysimpl_mount50: {:?}", r);

            //assert_eq!(r, 0, "Successfully mounted tmpfs");

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

            info!(
                "rump_init({}) done in {:?}, mounted tmpfs",
                ri,
                start.elapsed()
            );
        },
        core::ptr::null_mut(),
    );

    for i in 0..9999 {
        scheduler.run();
    }

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-rump"))]
pub fn main() {
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
        fn rump_pub_netconfig_ifcreate(iface: *const i8) -> i64;
        fn rump_pub_netconfig_dhcp_ipv4_oneshot(iface: *const i8) -> i64;
        fn rump_pub_netconfig_ipv4_gw(addr: *const i8) -> i64;
        fn rump_pub_netconfig_ipv4_ifaddr_cidr(iface: *const i8, addr: *const i8, mask: u32)
            -> i64;
        fn mount(typ: *const i8, path: *const i8, n: u64, args: *const tmpfs_args, argsize: usize);

        fn socket(domain: i64, typ: i64, protocol: i64) -> i64;
        fn htons(v: u16) -> u16;

        fn close(sock: i64) -> i64;
        fn rump_sys_fflush(sock: i64) -> i64;

        fn rump_schedule();
        fn rump_unschedule();

        fn rump___sysimpl_sendto(
            fd: i64,
            buf: *const i8,
            flags: i64,
            len: usize,
            addr: *const sockaddr_in,
            len: usize,
        ) -> i64;

        fn sysctlbyname(
            name: *const i8,
            oldp: *mut rumprt::c_void,
            oldlenp: *mut rumprt::c_size_t,
            newp: *const rumprt::c_void,
            newlen: rumprt::c_size_t,
        ) -> rumprt::c_int;

        //int connect(int s, const struct sockaddr *name, socklen_t namelen);
        fn connect(fd: i64, addr: *const sockaddr_in, len: usize) -> i64;
        fn write(fd: i64, buf: *const i8, len: usize) -> i64;

        fn rumpns_icmp_init();
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
            info!("rump___sysimpl_mount50: {:?}", r);

            let path = CStr::from_bytes_with_nul(b"wm0\0");
            let r = rump_pub_netconfig_dhcp_ipv4_oneshot(path.unwrap().as_ptr());
            assert_eq!(r, 0, "rump_pub_netconfig_dhcp_ipv4_oneshot");

            let AF_INET = 2;
            let SOCK_DGRAM = 2;
            let INADDR_ANY = 0;

            info!("before socket");
            let sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            info!("after socket");
            assert!(sockfd > 0);

            let addr = sockaddr_in {
                sin_len: core::mem::size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: (8889 as u16).to_be(),
                sin_addr: (2887712788 as u32).to_be(),
                zero: [0; 8],
            };

            /*let r = connect(
                sockfd,
                &addr as *const sockaddr_in,
                core::mem::size_of::<sockaddr_in>(),
            );
            assert_eq!(r, 0);
            info!("after conect");

            for i in 0..100 {
                info!("write msg = {}", i);

                use alloc::format;
                let buf = format!("pkt {}\n\0", i);
                let cstr = CStr::from_bytes_with_nul(buf.as_str().as_bytes()).unwrap();

                let r = write(sockfd, cstr.as_ptr() as *const i8, buf.len() as usize);
                assert_eq!(r, buf.len() as i64);

                //let _r = lineup::tls::Environment::thread().relinquish();
            }*/

            //rc = connect( sockfd, serverIter->ai_addr, serverIter->ai_addrlen);
            //(void) write( sockfd, TEST_MESSAGE, strlen(TEST_MESSAGE) );

            for i in 0..1212 {
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
                //let _r = lineup::tls::Environment::thread().relinquish();
            }

            let r = close(sockfd);
            assert_eq!(r, 0);

            info!(
                "rump_init({}) done in {:?}, mounted tmpfs",
                ri,
                start.elapsed()
            );

            loop {
                let t = lineup::tls::Environment::thread();
                //t.sleep(rawtime::Duration::from_secs(5));
                t.relinquish();
            }
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

    //for _i in 0..99999 {
    loop {
        scheduler.run();
    }

    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-buddy"))]
pub fn main() {
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
pub fn main() {
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-pfault"))]
pub fn main() {
    use arch::memory::{paddr_to_kernel_vaddr, PAddr};

    unsafe {
        let paddr = PAddr::from(1024 * 1024 * 1024 * 1);
        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);
        let ptr: *mut u64 = kernel_vaddr.as_mut_ptr();
        let val = *ptr;
        assert!(val != 0);
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-gpfault"))]
pub fn main() {
    // Note that int!(13) doesn't work in qemu. It doesn't push an error code properly for it.
    // So we cause a GP by loading garbage in the ss segment register.
    use x86::segmentation::{load_ss, SegmentSelector};
    unsafe {
        load_ss(SegmentSelector::new(99, x86::Ring::Ring3));
    }
}

#[cfg(all(feature = "integration-tests", feature = "test-alloc"))]
pub fn main() {
    use alloc::vec::Vec;
    {
        let mut buf: Vec<u8> = Vec::with_capacity(0);
        for i in 0..1024 {
            buf.push(i as u8);
        }
    } // Make sure we drop here.
    debug!("small allocations work.");

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
    debug!("large allocations work.");
    arch::debug::shutdown(ExitReason::Ok);
}

#[cfg(all(feature = "integration-tests", feature = "test-scheduler"))]
pub fn main() {
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
            debug!("lwt1 {:?}", Environment::tid());
        },
        core::ptr::null_mut(),
    );

    s.spawn(
        4096,
        |arg| {
            debug!("lwt2 {:?}", Environment::tid());
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
pub fn main() {
    info!("division = {}", 10.0 / 2.19);
    info!("division by zero = {}", 10.0 / 0.0);
    arch::debug::shutdown(ExitReason::Ok);
}
