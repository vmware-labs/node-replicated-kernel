// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![no_main]
#![feature(
    thread_local,
    alloc_error_handler,
    lang_items,
    core_intrinsics,
    asm_const,
    once_cell
)]

extern crate alloc;

use core::ptr;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "rumprt")]
use vibrio::rumprt;
use vibrio::sys_println;

use lineup::tls2::SchedulerControlBlock;
use log::{debug, error, info, Level};
use x86::bits64::paging::VAddr;

mod fs;
#[cfg(feature = "fxmark")]
mod fxmark;
mod histogram;
mod tests;
#[cfg(any(feature = "bench-vmops", feature = "bench-vmops-unmaplat"))]
mod vmops;

use crate::fs::{run_fio_syscall_proptests, run_fio_syscall_tests};

#[thread_local]
pub static mut TLS_TEST: [&str; 2] = ["abcd", "efgh"];

fn print_test() {
    let _r = vibrio::syscalls::Process::print("test\r\n");
    info!("print_test OK");
}

fn map_test() {
    let base: u64 = 0x0ef_ff000;
    let size: u64 = 0x1000 * 64;
    unsafe {
        vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");

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

fn alloc_physical_test() {
    use x86::bits64::paging::{PAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

    // Create base for the mapping
    let base: u64 = 0x0510_0000_0000;

    // Test allocation by checking to see if we can map it okay
    unsafe {
        // Allocate a base page of physical memory
        let (frame_id, paddr) = vibrio::syscalls::PhysicalMemory::allocate_base_page()
            .expect("Failed to get physical memory base page");
        info!("base frame id={:?}, paddr={:?}", frame_id, paddr);

        vibrio::syscalls::VSpace::map_frame(frame_id, base).expect("Failed to map base page");
        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, BASE_PAGE_SIZE);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);

        // We should not(?) be able to "map" it again if we specify the same
        // address
        //
        // This currently succeeds (and worse counts up the refcount), it should
        // probably fail with AlreadyMapped
        //
        //vibrio::syscalls::VSpace::map_frame(frame_id, base).expect("Failed to
        //map base page");

        // We should be able to "map" it again at a different address
        vibrio::syscalls::VSpace::map_frame(frame_id, base + 0x1000).expect("Can't map twice?");

        // We should be able to unmap it (then release frame will just release the frame id)
        vibrio::syscalls::VSpace::unmap(base, BASE_PAGE_SIZE as u64).expect("Unmap syscall failed");

        // We shouldn't be able to release it since it's still mapped once
        vibrio::syscalls::PhysicalMemory::release_frame(frame_id)
            .expect_err("Shouldn't be able to release physical memory base page yet");

        // We should be able to unmap it (then release frame will just release the frame id)
        vibrio::syscalls::VSpace::unmap(base + 0x1000, BASE_PAGE_SIZE as u64)
            .expect("Unmap syscall failed");

        // We shouldn't be able to release it since it's still mapped once
        vibrio::syscalls::PhysicalMemory::release_frame(frame_id)
            .expect("Now release_frame should succeed (unmapped everywhere)");
    }

    // Allocate a large page of physical memory
    let (frame_id2, paddr2) = vibrio::syscalls::PhysicalMemory::allocate_large_page()
        .expect("Failed to get physical memory large page");
    info!("large frame id={:?}, paddr={:?}", frame_id2, paddr2);

    // Test allocation by checking to see if we can map it okay
    unsafe {
        vibrio::syscalls::VSpace::map_frame(frame_id2, base).expect("Failed to map large page");
        let slice2: &mut [u8] = from_raw_parts_mut(base as *mut u8, LARGE_PAGE_SIZE);
        for i in slice2.iter_mut() {
            *i = 0xc;
        }
        assert_eq!(slice2[99], 0xc);
        vibrio::syscalls::VSpace::unmap(base, LARGE_PAGE_SIZE as u64)
            .expect("Unmap syscall failed");
    }

    // Release large page
    vibrio::syscalls::PhysicalMemory::release_frame(frame_id2)
        .expect("Failed to release physical memory large page");

    info!("phys_alloc_test OK");
}

// Just used for rackscale right now, not for standalone
fn request_core_remote_test() {
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;

    let threads = vibrio::syscalls::System::threads().expect("Can't get system topology");
    info!("threads: {:?}", threads);

    let core_id = vibrio::syscalls::System::core_id().expect("Can't get core id");

    let NUM_CLIENTS = 2; // TODO: this value change tests

    // Only one client will run this, because these are global IDs
    if core_id == 0 {
        for thread in threads.iter() {
            // Ignore core 0 on each client, assume it is already running init procress
            if thread.id >= NUM_CLIENTS {
                let r = vibrio::syscalls::Process::request_core(
                    thread.id, // in rackscale mode, thread.id is ignores - the ctoken is the valid value
                    VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
                );
                match r {
                    Ok(ctoken) => {
                        info!("Spawned core on {:?} <-> {}", ctoken, thread.id);
                    }
                    Err(_e) => {
                        panic!("Failed to spawn to core {}", thread.id);
                    }
                }
            }
        }

        /*
        for thread in threads {
                s.spawn(
                    32 * 4096,
                    move |_| {
                        info!(
                            "Hello from core {}",
                            lineup::tls2::Environment::scheduler().core_id
                        );
                    },
                    ptr::null_mut(),
                    thread.id,
                    None,
                );
        }
        */
    }
    info!("request_core_remote_test OK");

    // Run scheduler on core 0
    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    loop {
        s.run(&scb);
    }
}

fn scheduler_smp_test() {
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;

    let threads = vibrio::syscalls::System::threads().expect("Can't get system topology");

    for thread in threads.iter() {
        if thread.id != 0 {
            let r = vibrio::syscalls::Process::request_core(
                thread.id,
                VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
            );
            match r {
                Ok(ctoken) => {
                    info!("Spawned core on {:?} <-> {}", ctoken, thread.id);
                }
                Err(_e) => {
                    panic!("Failed to spawn to core {}", thread.id);
                }
            }
        }
    }

    for thread in threads {
        s.spawn(
            32 * 4096,
            move |_| {
                info!(
                    "Hello from core {}",
                    lineup::tls2::Environment::scheduler().core_id
                );
            },
            ptr::null_mut(),
            thread.id,
            None,
        );
    }

    // Run scheduler on core 0
    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    loop {
        s.run(&scb);
    }
}

fn scheduler_test() {
    use lineup::threads::ThreadId;
    let s: lineup::scheduler::SmpScheduler = Default::default();

    s.spawn(
        32 * 4096,
        move |_| {
            unsafe {
                info!("Hello from t1");
                assert_eq!(TLS_TEST[0], "abcd");
                assert_eq!(TLS_TEST[1], "efgh");
                TLS_TEST[0] = "xxxx";
                TLS_TEST[1] = "xxxx";
                assert_eq!(TLS_TEST[0], "xxxx");
            }
            assert_eq!(lineup::tls2::Environment::scheduler().core_id, 2);
            assert_eq!(lineup::tls2::Environment::thread().current_core, 2);
            assert_eq!(lineup::tls2::Environment::tid(), ThreadId(0));
        },
        ptr::null_mut(),
        2,
        None,
    );

    s.spawn(
        32 * 4096,
        move |_| {
            unsafe {
                assert_eq!(TLS_TEST[0], "abcd");
                assert_eq!(TLS_TEST[1], "efgh");
                info!("Hello from t2");
            }
            assert_eq!(lineup::tls2::Environment::scheduler().core_id, 2);
            assert_eq!(lineup::tls2::Environment::thread().current_core, 2);
            assert_eq!(lineup::tls2::Environment::tid(), ThreadId(1));
        },
        ptr::null_mut(),
        2,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(2);
    s.run(&scb);

    info!("scheduler_test OK");
}

#[allow(unused)] // it's used, but we do some feature hacking
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
        fn rump_init(fnptr: extern "C" fn()) -> u64;
        fn mount(typ: *const i8, path: *const i8, n: u64, args: *const tmpfs_args, argsize: usize);
        fn open(path: *const i8, opt: u64) -> i64;
        fn read(fd: i64, buf: *mut i8, bytes: u64) -> i64;
        fn write(fd: i64, buf: *const i8, bytes: u64) -> i64;
    }

    let up = lineup::upcalls::Upcalls {
        curlwp: rumprt::rumpkern_curlwp,
        deschedule: rumprt::rumpkern_unsched,
        schedule: rumprt::rumpkern_sched,
        context_switch: rumprt::prt::context_switch,
    };

    let mut scheduler = lineup::scheduler::SmpScheduler::with_upcalls(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(0);
            let ri = rump_init(ready);
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
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    scheduler.run(&scb);

    // TODO: Don't drop the scheduler for now,
    // so we don't panic because of unfinished generators:
    core::mem::forget(scheduler);
    info!("test_rump_tmpfs OK");
}

static READY_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn ready() {
    READY_FLAG.store(true, Ordering::Relaxed);
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

    #[repr(C)]
    struct timespec_t {
        tv_sec: i64,  // time_t
        tv_nsec: u64, // long
    }

    extern "C" {
        fn rump_boot_setsigmodel(sig: usize);
        fn rump_init(fnptr: extern "C" fn()) -> u64;
        fn rump_pub_netconfig_dhcp_ipv4_oneshot(iface: *const i8) -> i64;

        fn socket(domain: i64, typ: i64, protocol: i64) -> i64;
        fn sendto(
            fd: i64,
            buf: *const i8,
            len: usize,
            flags: i64,
            addr: *const sockaddr_in,
            len: usize,
        ) -> i64;
        fn close(sock: i64) -> i64;
        fn nanosleep(rqtp: *const timespec_t, rmtp: *mut timespec_t) -> i64;
    }

    let up = lineup::upcalls::Upcalls {
        curlwp: rumprt::rumpkern_curlwp,
        deschedule: rumprt::rumpkern_unsched,
        schedule: rumprt::rumpkern_sched,
        context_switch: rumprt::prt::context_switch,
    };

    let scheduler = lineup::scheduler::SmpScheduler::with_upcalls(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(1);
            let ri = rump_init(ready);
            assert_eq!(ri, 0);
            info!("rump_init({}) done in {:?}", ri, start.elapsed());
            while !READY_FLAG.load(Ordering::Relaxed) {
                let _r = lineup::tls2::Environment::thread().relinquish();
            }

            #[cfg(feature = "virtio")]
            let iface = b"vioif0\0";
            #[cfg(not(feature = "virtio"))]
            let iface = b"wm0\0";

            let iface = CStr::from_bytes_with_nul(iface);
            info!("before rump_pub_netconfig_dhcp_ipv4_oneshot");

            let r = rump_pub_netconfig_dhcp_ipv4_oneshot(iface.unwrap().as_ptr());
            assert_eq!(r, 0, "rump_pub_netconfig_dhcp_ipv4_oneshot");
            info!(
                "rump_pub_netconfig_dhcp_ipv4_oneshot done in {:?}",
                start.elapsed()
            );

            const AF_INET: i64 = 2;
            const SOCK_DGRAM: i64 = 2;

            const IPPROTO_UDP: i64 = 17;

            const MSG_DONTWAIT: i64 = 0x0080;

            let sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            assert!(sockfd > 0);
            info!("socket done in {:?}", start.elapsed());

            let addr = sockaddr_in {
                sin_len: core::mem::size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: (8889 as u16).to_be(),
                sin_addr: (2887712788 as u32).to_be(), // 172.31.0.20
                zero: [0; 8],
            };

            let _r = lineup::tls2::Environment::thread().relinquish();

            for i in 0..20 {
                info!("sendto msg = {}", i);
                use alloc::format;
                let buf = format!("pkt {}\n\0", i);
                let cstr = CStr::from_bytes_with_nul(buf.as_str().as_bytes()).unwrap();

                let r = sendto(
                    sockfd,
                    cstr.as_ptr() as *const i8,
                    buf.len(),
                    MSG_DONTWAIT,
                    &addr as *const sockaddr_in,
                    core::mem::size_of::<sockaddr_in>(),
                );
                assert_eq!(r, buf.len() as i64);
                core::mem::forget(cstr);

                // Add some sleep time here, as otherwise
                // we send the packet too fast and nothing appears on the other side
                // it seems after 6s (pkt 6) things start working.
                // I suspect it's due to some ARP resolution issue, but unclear.
                let sleep_dur = timespec_t {
                    tv_sec: 1,
                    tv_nsec: 0,
                };
                nanosleep(&sleep_dur as *const timespec_t, ptr::null_mut());
            }

            info!("test_rump_net OK");

            let r = close(sockfd);
            assert_eq!(r, 0);
        },
        core::ptr::null_mut(),
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    loop {
        scheduler.run(&scb);
    }
}

fn test_fs_invalid_addresses() {
    use vibrio::io::*;

    let invalid_str: &str = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts::<u8>(
            0x222_fee0 as *const u8,
            12,
        ))
    };
    let _ = vibrio::syscalls::Fs::open(
        invalid_str,
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .expect_err("Should not get Ok value");

    // Open a file to read and write on invalid addresses.
    let fd = vibrio::syscalls::Fs::open(
        "file1.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .expect("FileOpen syscall failed");
    assert_eq!(fd, 0);

    // In the rackscale architecture, we dereference the user-slice before we
    // try to read from the remote server, so while this test below (reading an
    // empty file with an invalid buffer) is allowed in POSIX and our x86 arch,
    // this currently will fail with rackscale. Luckily, I don't think it
    // matters much (and maybe should be the 'right' behavior anyways?):
    //
    //let mut invalid_slice0 = unsafe {
    //    core::slice::from_raw_parts_mut(0x1122_2fee0 as *mut u8, 11) }; let _r
    //= vibrio::syscalls::Fs::read(fd, &mut invalid_slice0).expect("read() on
    //    empty file is ok");

    // We need to write something for other calls to fail:
    vibrio::syscalls::Fs::write_at(fd, b"Hello, world!", 0).expect("write() syscall failed");

    let mut invalid_slice1 =
        unsafe { core::slice::from_raw_parts_mut(0x2222_2fee0 as *mut u8, 256) };
    let _r = vibrio::syscalls::Fs::write(fd, &invalid_slice1).expect_err("write() did not fail");
    let _r = vibrio::syscalls::Fs::getinfo("").expect_err("getinfo() did not fail");
    let mut invalid_slice2 =
        unsafe { core::slice::from_raw_parts_mut(0x3322_2fee0 as *mut u8, 11) };
    let _r = vibrio::syscalls::Fs::read(fd, &mut invalid_slice2).expect_err("read() did not fail");

    // Test address validity small pages.
    let base_small: u64 = 0x10000;
    let size_small: u64 = 0x1000;
    unsafe {
        vibrio::syscalls::VSpace::map(base_small, size_small).expect("Map syscall failed");
    }
    let slice: &mut [u8] =
        unsafe { from_raw_parts_mut(base_small as *mut u8, size_small as usize) };
    for i in slice.iter_mut() {
        *i = 0xb;
    }

    for (ptr, len) in [
        ((base_small + size_small + 1), 256),
        ((base_small + size_small - 1), 256),
        (base_small, size_small as usize + 1),
        ((base_small - 1), 256),
    ] {
        let invalid_slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
        let _ret = vibrio::syscalls::Fs::write(fd, invalid_slice)
            .expect_err("FileWrite syscall should fail");
    }

    // Test address validity large pages.
    let base_large: u64 = 0x8000000;
    let size_large: u64 = 0x200000;
    unsafe {
        vibrio::syscalls::VSpace::map(base_large, size_large).expect("Map syscall failed");
    }
    let slice: &mut [u8] =
        unsafe { from_raw_parts_mut(base_large as *mut u8, size_large as usize) };
    for i in slice.iter_mut() {
        *i = 0xb;
    }

    for (ptr, len) in [
        ((base_large + size_large + 1), 256),
        ((base_large + size_large - 1), 256),
        (base_large, size_large as usize + 1),
        ((base_large - 1), 256),
    ] {
        let invalid_slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
        let _ret = vibrio::syscalls::Fs::write(fd, invalid_slice)
            .expect_err("FileWrite syscall should fail");
    }

    // Close the opened file.
    let _ret = vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
}

fn fs_test() {
    use vibrio::io::*;
    let base: u64 = 0x1ef_ff000;
    let size: u64 = 0x1000 * 64;
    unsafe {
        // Create a directory
        let _ret = vibrio::syscalls::Fs::mkdir_simple("mydir", FileModes::S_IRWXU)
            .expect("MkDir syscall failed");

        // Open a file
        let fd = vibrio::syscalls::Fs::open(
            "mydir/file.txt",
            FileFlags::O_RDWR | FileFlags::O_CREAT,
            FileModes::S_IRWXU,
        )
        .expect("FileOpen syscall failed");
        assert_eq!(fd, 0);

        // Allocate a buffer and write data into it, which is later written to the file.
        vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");

        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);

        // Write the slice content to the created file.
        let ret = vibrio::syscalls::Fs::write_at(fd, &slice[0..256], 0)
            .expect("FileWrite syscall failed");
        assert_eq!(ret, 256);

        let fileinfo =
            vibrio::syscalls::Fs::getinfo("mydir/file.txt").expect("GetInfo syscall failed");
        assert_eq!(fileinfo.fsize, 256);
        assert_eq!(fileinfo.ftype, FileType::File.into());

        // Reset the slice content. And read the file content from the file and
        // check if it's same as the date which was written to the file.
        for i in slice.iter_mut() {
            *i = 0;
        }
        let ret =
            vibrio::syscalls::Fs::read(fd, &mut slice[0..256]).expect("FileWrite syscall failed");
        assert_eq!(ret, 256);
        assert_eq!(slice[255], 0xb);
        assert_eq!(slice[256], 0);

        // This call is to tests nrk memory deallocator for large allocations.
        let _r = vibrio::syscalls::Fs::write_at(fd, &slice[0..256], 4096 * 255)
            .expect("FileWriteAt syscall failed");

        // Close the file.
        vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");

        // Rename the file
        let ret = vibrio::syscalls::Fs::rename("mydir/file.txt", "filenew.txt")
            .expect("FileRename syscall failed");

        // Delete the file.
        vibrio::syscalls::Fs::delete("filenew.txt").expect("FileDelete syscall failed");

        let ret =
            vibrio::syscalls::Fs::delete("mydir").expect("FileDelete syscall on directory failed");

        // Test fs with invalid userspace pointers
        test_fs_invalid_addresses();
    }

    run_fio_syscall_tests();
    info!("fs_test OK");
}

fn fs_prop_test() {
    run_fio_syscall_proptests();
    info!("fs_prop_test OK");
}

fn pmem_alloc(ncores: Option<usize>) {
    use alloc::vec::Vec;
    use lineup::tls2::Environment;

    unsafe extern "C" fn bencher_trampoline(_arg1: *mut u8) -> *mut u8 {
        map();
        ptr::null_mut()
    }

    fn map() {
        let core_id = Environment::scheduler().core_id as u64;
        let size: u64 = 0x1000;
        let base: u64 = 0x3ef_f000 + core_id * size;
        unsafe {
            // Allocate a buffer and write data into it, which is later written to the file.
            vibrio::syscalls::VSpace::map_pmem(base, size).expect("Map syscall failed");

            let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
            for i in slice.iter_mut() {
                *i = 0xb;
            }
            assert_eq!(slice[99], 0xb);
        }
    }

    let hwthreads = vibrio::syscalls::System::threads().expect("Can't get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;
    let cores = ncores.unwrap_or(hwthreads.len());

    let mut maximum = 1; // We already have core 0
    for hwthread in hwthreads.iter().take(cores) {
        if hwthread.id != 0 {
            match vibrio::syscalls::Process::request_core(
                hwthread.id,
                VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
            ) {
                Ok(_) => {
                    maximum += 1;
                    continue;
                }
                Err(e) => {
                    error!("Can't spawn on {:?}: {:?}", hwthread.id, e);
                    break;
                }
            }
        }
    }
    info!("Spawned {} cores", maximum);

    s.spawn(
        32 * 4096,
        move |_| {
            for idx in maximum..maximum + 1 {
                let mut thandles = Vec::with_capacity(idx);

                for core_id in 0..idx {
                    thandles.push(
                        Environment::thread()
                            .spawn_on_core(Some(bencher_trampoline), idx as *mut u8, core_id)
                            .expect("Can't spawn bench thread?"),
                    );
                }

                for thandle in thandles {
                    Environment::thread().join(thandle);
                }
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    while s.has_active_threads() {
        s.run(&scb);
    }
    info!("pmem_alloc OK");
}

pub fn install_vcpu_area() {
    let ctl =
        vibrio::syscalls::Process::vcpu_control_area().expect("Can't read vcpu control area.");
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

    let pinfo = vibrio::syscalls::Process::process_info().expect("Can't read process info");

    #[cfg(feature = "fxmark")]
    {
        use core::str::FromStr;
        //python3 ./run.py --kfeature test-userspace --ufeatures fxmark --qemu-cores 1 --cmd initargs=1xdrbl
        let (ncores, open_files, benchmark, write_ratio) =
            match fxmark::ARGs::from_str(pinfo.cmdline) {
                Ok(args) => (
                    Some(args.cores),
                    args.open_files,
                    args.benchmark,
                    args.write_ratio,
                ),
                Err(_) => unreachable!(),
            };
        fxmark::bench(ncores, open_files, benchmark, write_ratio);
        vibrio::syscalls::Process::exit(0);
    }

    let ncores: Option<usize> = pinfo.cmdline.parse().ok();

    #[cfg(feature = "bench-vmops")]
    vmops::bench(ncores);

    #[cfg(feature = "bench-vmops-unmaplat")]
    vmops::unmaplat::bench(ncores);

    #[cfg(feature = "test-print")]
    print_test();

    #[cfg(feature = "test-syscalls")]
    tests::syscalls();

    #[cfg(feature = "test-rpc")]
    rpc_test();

    #[cfg(feature = "test-upcall")]
    upcall_test();

    #[cfg(feature = "test-map")]
    map_test();

    #[cfg(feature = "test-alloc")]
    alloc_test();

    #[cfg(feature = "test-pmem-alloc")]
    pmem_alloc(ncores);

    #[cfg(feature = "test-phys-alloc")]
    alloc_physical_test();

    #[cfg(feature = "test-request-core-remote")]
    request_core_remote_test();

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

    #[cfg(feature = "test-fs-prop")]
    fs_prop_test();

    vibrio::vconsole::init();

    #[cfg(feature = "test-scheduler-smp")]
    scheduler_smp_test();

    debug!("Done with init tests, if we came here probably everything is good.");
    vibrio::syscalls::Process::exit(0);
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
