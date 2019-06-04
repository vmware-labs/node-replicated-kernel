#![no_std]
#![no_main]
#![feature(asm, alloc_error_handler, const_fn, panic_info_message)]

extern crate alloc;
extern crate spin;

extern crate lineup;

use alloc::format;
use alloc::vec::Vec;

use core::alloc::{GlobalAlloc, Layout};
use core::mem::transmute;
use core::panic::PanicInfo;
use core::ptr;
use core::slice::from_raw_parts_mut;

use vibrio::rumprt;
use vibrio::{sys_print, sys_println};

use log::{debug, error, info};
use log::{Level, Metadata, Record, SetLoggerError};

#[global_allocator]
static MEM_PROVIDER: vibrio::mem::SafeZoneAllocator =
    vibrio::mem::SafeZoneAllocator::new(&vibrio::mem::PAGER);

fn print_test() {
    vibrio::syscalls::print("test\r\n");
    info!("log test");
}

fn map_test() {
    let base: u64 = 0xff000;
    let size: u64 = 0x1000 * 64;
    unsafe {
        vibrio::syscalls::vspace(vibrio::syscalls::VSpaceOperation::Map, base, size);

        let mut slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);
    }
}

fn alloc_test() {
    use alloc::vec::Vec;
    let mut v: Vec<u16> = Vec::with_capacity(256);

    for e in 0..256 {
        v.push(e);
    }

    assert_eq!(v[255], 255);
    assert_eq!(v.len(), 256);
}

fn scheduler_test() {
    vibrio::syscalls::print("scheduler test");
    use lineup::DEFAULT_UPCALLS;
    let mut s = lineup::Scheduler::new(DEFAULT_UPCALLS);

    s.spawn(
        32 * 4096,
        move |_| {
            info!("weee from t1");
        },
        ptr::null_mut(),
    );

    s.spawn(
        32 * 4096,
        move |_| {
            info!("weee from t2");
        },
        ptr::null_mut(),
    );

    s.run();
}

fn rumprt_test() {
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
        ta_root_mode: u32, // mode_t		ta_root_mode;
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
            info!("rump_init({}) done in {:?}", ri, start.elapsed());

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

            //arch::debug::shutdown(ExitReason::Ok);
            vibrio::syscalls::exit(1);
        },
        core::ptr::null_mut(),
    );

    loop {
        scheduler.run();
    }
}

pub fn test_rump_net() {
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
            info!("before rump_pub_netconfig_dhcp_ipv4_oneshot");

            let r = rump_pub_netconfig_dhcp_ipv4_oneshot(iface.unwrap().as_ptr());
            assert_eq!(r, 0, "rump_pub_netconfig_dhcp_ipv4_oneshot");
            info!(
                "rump_pub_netconfig_dhcp_ipv4_oneshot done in {:?}",
                start.elapsed()
            );

            let AF_INET = 2;
            let SOCK_DGRAM = 2;

            let sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            assert!(sockfd > 0);
            info!("socket done in {:?}", start.elapsed());

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
                vibrio::rumprt::dev::irq_handler(core::ptr::null_mut());
                unreachable!("should not exit");
            },
            core::ptr::null_mut(),
        )
        .expect("Can't create IRQ thread?");

    loop {
        scheduler.run();
    }
}

pub fn install_vcpu_area() {
    use x86::bits64::paging::VAddr;
    vibrio::syscalls::vcpu_control_area(VAddr::from(0x32eef0000u64), VAddr::from(0x32eef1000u64))
        .expect("Can't install vcpu control area");
}

pub fn upcall_test() {
    sys_println!("causing a debug exception");
    unsafe { x86::int!(3) };
    sys_println!("hopefully we arrive here again?");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        log::set_logger(&vibrio::writer::LOGGER)
            .map(|()| log::set_max_level(Level::Debug.to_level_filter()));
    }
    debug!("INIT LOGGING");

    install_vcpu_area();

    print_test();

    upcall_test();

    map_test();
    alloc_test();
    scheduler_test();
    //rumprt_test();
    test_rump_net();

    debug!("DONE WITH INIT");

    vibrio::syscalls::exit(0);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    sys_println!("System panic encountered");
    if let Some(message) = info.message() {
        sys_print!(": '{}'", message);
    }
    if let Some(location) = info.location() {
        sys_println!(" in {}:{}", location.file(), location.line());
    } else {
        sys_println!("");
    }

    vibrio::syscalls::exit(1);
    loop {}
}

#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    panic!("oom {:?}", layout)
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum _Unwind_Reason_Code {
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8,
}

#[allow(non_camel_case_types)]
pub struct _Unwind_Context;

#[allow(non_camel_case_types)]
pub type _Unwind_Action = u32;
static _UA_SEARCH_PHASE: _Unwind_Action = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct _Unwind_Exception {
    exception_class: u64,
    exception_cleanup: fn(_Unwind_Reason_Code, *const _Unwind_Exception),
    private: [u64; 2],
}

#[cfg_attr(target_os = "none", lang = "eh_personality")]
#[no_mangle]
pub fn rust_eh_personality(
    _version: isize,
    _actions: _Unwind_Action,
    _exception_class: u64,
    _exception_object: &_Unwind_Exception,
    _context: &_Unwind_Context,
) -> _Unwind_Reason_Code {
    loop {}
}

#[no_mangle]
#[allow(non_snake_case)]
pub fn _Unwind_Resume() {
    loop {}
}
