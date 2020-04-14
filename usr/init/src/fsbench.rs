//! A simple file system benchmark.

use core::ptr;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::{debug, error, info};
use x86::bits64::paging::VAddr;
use x86::random::rdrand16;

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

pub fn bench(is_write: bool, is_random: bool, share_file: bool, num_cores: usize) {
    use lineup::threads::ThreadId;
    use lineup::tls2::{Environment, SchedulerControlBlock};

    let s = &vibrio::upcalls::PROCESS_SCHEDULER;

    let threads = vibrio::syscalls::System::threads().expect("Can't get system topology");
    assert!(threads.len() >= num_cores);

    for thread in threads {
        if thread.id == 0 || thread.id >= num_cores {
            continue;
        }

        let r = vibrio::syscalls::Process::request_core(
            thread.id,
            VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
        );
        match r {
            Ok(_ctoken) => {
                s.spawn(
                    32 * 4096,
                    move |_| unsafe {
                        POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
                        if is_write {
                            write_bench(
                                lineup::tls2::Environment::scheduler().core_id,
                                is_random,
                                share_file,
                            );
                        } else {
                            read_bench(
                                lineup::tls2::Environment::scheduler().core_id,
                                is_random,
                                share_file,
                            );
                        }
                    },
                    ptr::null_mut(),
                    thread.id,
                );
            }
            Err(_e) => {
                error!("Failed to spawn to core {}", thread.id);
            }
        };
    }

    s.spawn(
        32 * 4096,
        move |_| unsafe {
            POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
            if is_write {
                write_bench(
                    lineup::tls2::Environment::scheduler().core_id,
                    is_random,
                    share_file,
                );
            } else {
                read_bench(
                    lineup::tls2::Environment::scheduler().core_id,
                    is_random,
                    share_file,
                );
            }
        },
        ptr::null_mut(),
        0,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    while s.has_active_threads() {
        s.run(&scb);
    }
}

pub fn write_bench(core_id: usize, random: bool, shared: bool) {
    use alloc::format;
    use vibrio::io::*;
    use vibrio::syscalls::*;

    let size: u64 = 4096;
    let num_pages = 2047;
    let file_size = num_pages * size;
    let base: u64 = 0xff000 + (core_id as u64 * file_size);
    let mut file_name = format!("file.txt");

    unsafe {
        // Allocate a buffer and write data into it, which is later written to the file.
        VSpace::map(base, size).expect("Map syscall failed");

        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }

        if !shared {
            file_name = format!("file.txt{}", core_id);
        }
        // Open the file.
        let fd = Fs::open(
            file_name.as_ptr() as u64,
            u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
            u64::from(FileModes::S_IRWXU),
        )
        .expect("FileOpen syscall failed");

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
        while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let mut iops = 0;
        let mut iterations = 10;
        let mut rand: u16 = 0;
        while iterations > 0 {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                let offset;
                if random {
                    // rdrand16 is slightly cheaper than rdrand32/64.
                    rdrand16(&mut rand);
                    offset = rand % file_size as u16;
                } else {
                    offset = ((iops * size) % file_size) as u16;
                }
                let ret = Fs::write_at(fd, slice.as_ptr() as u64, 4096, 0 as i64)
                    .expect("FileRead syscall failed");
                iops += 1;
            }
            iterations -= 1;
        }
        info!("{},{},write", core_id, iops / 10);

        //TODO: Delete crashes due to memory deallocation bug.
        let ret = Fs::delete(file_name.as_ptr() as u64).expect("FileDelete syscall failed");
    }
}

pub fn read_bench(core_id: usize, random: bool, shared: bool) {
    use alloc::format;
    use vibrio::io::*;
    use vibrio::syscalls::*;

    let size: u64 = 4096;
    let num_pages = 2047;
    let file_size = num_pages * size;
    let base: u64 = 0xff000 + (core_id as u64 * file_size);
    let mut file_name = format!("file.txt");

    unsafe {
        // Allocate a buffer and write data into it, which is later written to the file.
        VSpace::map(base, size).expect("Map syscall failed");

        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }

        if !shared {
            file_name = format!("file.txt{}", core_id);
        }
        // Open the file.
        let fd = Fs::open(
            file_name.as_ptr() as u64,
            u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
            u64::from(FileModes::S_IRWXU),
        )
        .expect("FileOpen syscall failed");

        let ret = Fs::write_at(fd, slice.as_ptr() as u64, 4096, file_size as i64)
            .expect("FileWrite syscall failed");

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
        while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let mut iops = 0;
        let mut iterations = 10;
        let mut rand: u16 = 0;
        while iterations > 0 {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                let offset;
                if random {
                    // rdrand16 is slightly cheaper than rdrand32/64.
                    rdrand16(&mut rand);
                    offset = rand % file_size as u16;
                } else {
                    offset = ((iops * size) % file_size) as u16;
                }
                let ret = Fs::read_at(fd, slice.as_ptr() as u64, 4096, offset as i64)
                    .expect("FileRead syscall failed");
                iops += 1;
            }
            iterations -= 1;
        }
        info!("{},{},read", core_id, iops / 10);

        //TODO: Delete crashes due to memory deallocation bug.
        let ret = Fs::delete(file_name.as_ptr() as u64).expect("FileDelete syscall failed");
    }
}
