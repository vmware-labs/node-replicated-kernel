// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, MAX_OPEN_FILES, PAGE_SIZE};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::RefCell;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use vibrio::io::*;
use x86::random::rdrand16;

#[derive(Clone)]
pub struct MIX {
    page: Vec<u8>,
    size: i64,
    cores: RefCell<usize>,
    max_open_files: usize,
    open_files: RefCell<usize>,
    fds: RefCell<Vec<u64>>,
}

impl Default for MIX {
    fn default() -> MIX {
        let base: u64 = 0xff000;
        let size: u64 = 0x1000;
        // Allocate a buffer and write data into it, which is later written to the file.
        let page = alloc::vec![0xb; 4096];
        let fd = vec![u64::MAX; 512];

        MIX {
            page,
            size: 256 * 1024 * 1024,
            cores: RefCell::new(0),
            max_open_files: MAX_OPEN_FILES.load(Ordering::Acquire),
            open_files: RefCell::new(0),
            fds: RefCell::new(fd),
        }
    }
}

impl Bench for MIX {
    fn init(&self, cores: Vec<usize>, open_files: usize) {
        *self.cores.borrow_mut() = cores.len();
        *self.open_files.borrow_mut() = open_files;
        for file_num in 0..open_files {
            let file_name = format!("file{}.txt\0", file_num);
            unsafe {
                let fd = vibrio::syscalls::Fs::open(
                    file_name.as_ptr() as u64,
                    u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
                    u64::from(FileModes::S_IRWXU),
                )
                .expect("FileOpen syscall failed");

                let ret = vibrio::syscalls::Fs::write_at(
                    fd,
                    self.page.as_ptr() as u64,
                    PAGE_SIZE,
                    self.size,
                )
                .expect("FileWriteAt syscall failed");
                assert_eq!(ret, PAGE_SIZE as u64);
                self.fds.borrow_mut()[file_num] = fd;
            }
        }
    }

    fn run(
        &self,
        POOR_MANS_BARRIER: &AtomicUsize,
        duration: u64,
        core: usize,
        write_ratio: usize,
    ) -> Vec<usize> {
        use vibrio::io::*;
        use vibrio::syscalls::*;
        let mut iops_per_second = Vec::with_capacity(duration as usize);

        let file_num = (core % self.max_open_files) % *self.open_files.borrow();
        let fd = self.fds.borrow()[file_num];
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let total_pages: usize = self.size as usize / 4096;
        let page: &mut [i8; PAGE_SIZE as usize] = &mut [0; PAGE_SIZE as usize];
        vibrio::syscalls::Fs::write_at(fd, page.as_ptr() as u64, PAGE_SIZE, self.size);

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Release);
        while POOR_MANS_BARRIER.load(Ordering::Acquire) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let mut iops = 0;
        let mut iterations = 0;
        let mut random_num: u16 = 0;

        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for i in 0..64 {
                    unsafe { rdrand16(&mut random_num) };
                    let rand = random_num as usize % total_pages;
                    let offset = rand * 4096;

                    if random_num as usize % 100 < write_ratio {
                        if vibrio::syscalls::Fs::write_at(
                            fd,
                            page.as_ptr() as u64,
                            PAGE_SIZE,
                            offset as i64,
                        )
                        .expect("FileWriteAt syscall failed")
                            != PAGE_SIZE
                        {
                            panic!("MIX: write_at() failed");
                        }
                    } else {
                        if vibrio::syscalls::Fs::read_at(
                            fd,
                            page.as_ptr() as u64,
                            PAGE_SIZE,
                            offset as i64,
                        )
                        .expect("FileReadAt syscall failed")
                            != PAGE_SIZE
                        {
                            panic!("MIX: read_at() failed");
                        }
                    }
                    iops += 1;
                }
            }

            iops_per_second.push(iops);
            iterations += 1;
            iops = 0;
        }

        POOR_MANS_BARRIER.fetch_add(1, Ordering::Release);
        let num_cores = *self.cores.borrow();
        // To avoid explicit GC in mlnr.
        while POOR_MANS_BARRIER.load(Ordering::Acquire) != num_cores {
            vibrio::syscalls::Fs::read_at(fd, page.as_ptr() as u64, 1, 0);
        }

        if core == 0 {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {}
            for i in 0..*self.open_files.borrow() {
                let fd = self.fds.borrow()[i];
                vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
            }
        }
        iops_per_second.clone()
    }
}

unsafe impl Sync for MIX {}
