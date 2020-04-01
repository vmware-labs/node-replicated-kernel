#![no_std]
#![no_main]
#![feature(asm, alloc_error_handler, const_fn, panic_info_message)]
#![allow(unused_imports, dead_code)]
extern crate alloc;
extern crate spin;
extern crate vibrio;

extern crate lineup;

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::ptr;
use core::slice::from_raw_parts_mut;

#[cfg(feature = "rumprt")]
use vibrio::rumprt;
use vibrio::{sys_print, sys_println};

use lineup::tls2::SchedulerControlBlock;

use log::{debug, error, info};
use log::{Level, Metadata, Record, SetLoggerError};

fn print_test() {
    let _r = vibrio::syscalls::print("test\r\n");
    info!("print_test OK");
}

fn map_test() {
    let base: u64 = 0xff000;
    let size: u64 = 0x1000 * 64;
    unsafe {
        vibrio::syscalls::vspace(vibrio::syscalls::VSpaceOperation::Map, base, size)
            .expect("Map syscall failed");

        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);
    }

    info!("map_test OK");
}

fn alloc_test() {
    use alloc::vec::Vec;
    let mut v: Vec<u16> = Vec::with_capacity(256);

    for e in 0..256 {
        v.push(e);
    }

    assert_eq!(v[255], 255);
    assert_eq!(v.len(), 256);
    info!("alloc_test OK");
}

fn scheduler_test() {
    let mut s: lineup::scheduler::SmpScheduler = Default::default();

    s.spawn(
        32 * 4096,
        move |_| {
            info!("Hello from t1");
        },
        ptr::null_mut(),
        0
    );

    s.spawn(
        32 * 4096,
        move |_| {
            info!("Hello from t2");
        },
        ptr::null_mut(),
        0
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    s.run(&scb);

    info!("scheduler_test OK");
}

#[cfg(feature = "rumprt")]
fn test_rump_tmpfs() {
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

    let up = lineup::upcalls::Upcalls {
        curlwp: rumprt::rumpkern_curlwp,
        deschedule: rumprt::rumpkern_unsched,
        schedule: rumprt::rumpkern_sched,
    };

    let mut scheduler = lineup::scheduler::SmpScheduler::with_upcalls(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(0);
            let ri = rump_init();
            assert_eq!(ri, 0);
            info!("rump_init({}) done in {:?}", ri, start.elapsed());

            const TMPFS_ARGS_VERSION: u64 = 1;

            let tfsa = tmpfs_args {
                ta_version: TMPFS_ARGS_VERSION,
                ta_nodes_max: 0,
                ta_size_max: 1 * 1024 * 1024,
                ta_root_uid: 0,
                ta_root_gid: 0,
                ta_root_mode: 0o1777,
            };

            let path = CStr::from_bytes_with_nul(b"/tmp\0");
            let tmpfs_ident = CStr::from_bytes_with_nul(b"tmpfs\0");
            info!("mounting tmpfs");

            let _r = mount(
                tmpfs_ident.unwrap().as_ptr(),
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
        },
        core::ptr::null_mut(),
        0
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    scheduler.run(&scb);

    // TODO: Don't drop the scheduler for now,
    // so we don't panic because of unfinished generators:
    core::mem::forget(scheduler);
    info!("test_rump_tmpfs OK");
}

#[cfg(feature = "rumprt")]
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

    let up = lineup::upcalls::Upcalls {
        curlwp: rumprt::rumpkern_curlwp,
        deschedule: rumprt::rumpkern_unsched,
        schedule: rumprt::rumpkern_sched,
    };

    let mut scheduler = lineup::scheduler::SmpScheduler::with_upcalls(up);
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

            const AF_INET: i64 = 2;
            const SOCK_DGRAM: i64 = 2;

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
                let _r = lineup::tls2::Environment::thread().relinquish();
            }

            info!("test_rump_net OK");

            let r = close(sockfd);
            assert_eq!(r, 0);
        },
        core::ptr::null_mut(),
        0
    );

    scheduler
        .spawn(
            32 * 1024,
            |_yielder| unsafe {
                vibrio::rumprt::dev::irq_handler(core::ptr::null_mut());
                unreachable!("should not exit");
            },
            core::ptr::null_mut(),
            0
        )
        .expect("Can't create IRQ thread?");

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    loop {
        scheduler.run(&scb);
    }
}

fn fs_test() {
    use vibrio::io::*;
    let base: u64 = 0xff000;
    let size: u64 = 0x1000 * 64;
    unsafe {
        // Open a file
        let fd = vibrio::syscalls::file_open(
            vibrio::syscalls::FileOperation::Open,
            "file.txt\0".as_ptr() as u64,
            u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
            u64::from(FileModes::S_IRWXU),
        )
        .expect("FileOpen syscall failed");
        assert_eq!(fd, 0);

        // Allocate a buffer and write data into it, which is later written to the file.
        vibrio::syscalls::vspace(vibrio::syscalls::VSpaceOperation::Map, base, size)
            .expect("Map syscall failed");

        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);

        // Write the slice content to the created file.
        let ret = vibrio::syscalls::fileio(
            vibrio::syscalls::FileOperation::Write,
            fd,
            slice.as_ptr() as u64,
            256,
        )
        .expect("FileWrite syscall failed");
        assert_eq!(ret, 256);

        let fileinfo = vibrio::syscalls::file_getinfo(
            vibrio::syscalls::FileOperation::GetInfo,
            "file.txt\0".as_ptr() as u64,
        )
        .expect("FileOpen syscall failed");
        assert_eq!(fileinfo.fsize, 256);
        assert_eq!(fileinfo.ftype, rumprt::Rump_FileType::File as u64);

        // Reset the slice content. And read the file content from the file and
        // check if it's same as the date which was written to the file.
        for i in slice.iter_mut() {
            *i = 0;
        }
        let ret = vibrio::syscalls::fileio(
            vibrio::syscalls::FileOperation::Read,
            fd,
            slice.as_ptr() as u64,
            256,
        )
        .expect("FileWrite syscall failed");
        assert_eq!(ret, 256);
        assert_eq!(slice[255], 0xb);
        assert_eq!(slice[256], 0);

        // Close the file.
        let ret = vibrio::syscalls::file_close(vibrio::syscalls::FileOperation::Close, fd)
            .expect("FileClose syscall failed");
        assert_eq!(ret, 0);

        // Delete the file.
        let ret = vibrio::syscalls::file_delete(
            vibrio::syscalls::FileOperation::Delete,
            "file.txt\0".as_ptr() as u64,
        )
        .expect("FileDelete syscall failed");
        assert_eq!(ret, true);
    }

    info!("fs_test OK");
}

pub fn install_vcpu_area() {
    use x86::bits64::paging::VAddr;
    let ctl = vibrio::syscalls::vcpu_control_area().expect("Can't read vcpu control area.");
    ctl.resume_with_upcall =
        VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64);
}

pub fn upcall_test() {
    sys_println!("causing a debug exception");
    unsafe { x86::int!(3) };
    info!("upcall_test OK");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        log::set_logger(&vibrio::writer::LOGGER)
            .map(|()| log::set_max_level(Level::Debug.to_level_filter()))
            .expect("Can't set-up logging");
    }
    debug!("Initialized logging");
    install_vcpu_area();

    #[cfg(feature = "test-print")]
    print_test();

    #[cfg(feature = "test-upcall")]
    upcall_test();

    #[cfg(feature = "test-map")]
    map_test();

    #[cfg(feature = "test-alloc")]
    alloc_test();

    #[cfg(feature = "test-scheduler")]
    scheduler_test();

    #[cfg(feature = "rumprt")]
    {
        // Run either, test-rump-net or test-rump-tmpfs
        // TODO: Can't run both together at the moment, I suspect it is due to
        // the IRQ thread being statically 'hacked' as thread#1 in virbio/upcalls.rs
        #[cfg(all(not(feature = "test-rump-net"), feature = "test-rump-tmpfs"))]
        test_rump_tmpfs();
        #[cfg(all(not(feature = "test-rump-tmpfs"), feature = "test-rump-net"))]
        test_rump_net();
    }

    #[cfg(feature = "test-fs")]
    fs_test();

    debug!("Done with init tests, if we came here probably everything is good.");
    vibrio::syscalls::exit(0);
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
