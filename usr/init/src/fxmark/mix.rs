// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, MAX_OPEN_FILES, PAGE_SIZE};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use lineup::core_id_to_index;
use vibrio::io::*;
use x86::random::rdrand16;

#[derive(Clone)]
pub struct MIX {
    page: Vec<u8>,
    size: i64,
    cores: RefCell<usize>,
    min_core: RefCell<usize>,
    max_open_files: usize,
    open_files: RefCell<usize>,
    fds: RefCell<Vec<u64>>,
}

impl Default for MIX {
    fn default() -> MIX {
        // Allocate a buffer and write data into it, which is later written to the file.
        let page = alloc::vec![0xb; PAGE_SIZE as usize];
        let fd = vec![u64::MAX; 512];

        MIX {
            page,
            size: 256 * 1024 * 1024,
            cores: RefCell::new(0),
            min_core: RefCell::new(0),
            max_open_files: MAX_OPEN_FILES.load(Ordering::Acquire),
            open_files: RefCell::new(0),
            fds: RefCell::new(fd),
        }
    }
}

impl Bench for MIX {
    fn init(&self, cores: Vec<usize>, open_files: usize) {
        *self.cores.borrow_mut() = cores.len();
        *self.min_core.borrow_mut() = *cores.iter().min().unwrap();
        *self.open_files.borrow_mut() = open_files;
        for file_num in 0..open_files {
            let fd = vibrio::syscalls::Fs::open(
                format!("file{}.txt", file_num),
                FileFlags::O_RDWR | FileFlags::O_CREAT,
                FileModes::S_IRWXU,
            )
            .expect("FileOpen syscall failed");

            let ret = vibrio::syscalls::Fs::write_at(fd, &self.page, self.size)
                .expect("FileWriteAt syscall failed");
            assert_eq!(ret, PAGE_SIZE as u64);
            self.fds.borrow_mut()[file_num] = fd;
        }
    }

    fn run(
        &self,
        poor_mans_barrier: &AtomicUsize,
        duration: u64,
        core: usize,
        write_ratio: usize,
    ) -> Vec<usize> {
        let mut iops_per_second = Vec::with_capacity(duration as usize);

        let file_num = (core_id_to_index(core) % self.max_open_files) % *self.open_files.borrow();
        let fd = self.fds.borrow()[file_num];
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let total_pages: usize = self.size as usize / 4096;
        let page: &mut [u8; PAGE_SIZE as usize] = &mut [0; PAGE_SIZE as usize];
        vibrio::syscalls::Fs::write_at(fd, page, self.size).expect("can't write_at");

        // Synchronize with all cores
        poor_mans_barrier.fetch_sub(1, Ordering::Release);
        while poor_mans_barrier.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }

        let mut iops = 0;
        let mut iterations = 0;
        let mut random_num: u16 = 0;

        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for _i in 0..64 {
                    unsafe { rdrand16(&mut random_num) };
                    let rand = random_num as usize % total_pages;
                    let offset = rand * 4096;

                    if random_num as usize % 100 < write_ratio {
                        if vibrio::syscalls::Fs::write_at(fd, page, offset as i64)
                            .expect("FileWriteAt syscall failed")
                            != PAGE_SIZE
                        {
                            panic!("MIX: write_at() failed");
                        }
                    } else {
                        if vibrio::syscalls::Fs::read_at(fd, page, offset as i64)
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

        poor_mans_barrier.fetch_add(1, Ordering::Release);
        let num_cores = *self.cores.borrow();
        // To avoid explicit GC in mlnr.
        while poor_mans_barrier.load(Ordering::Acquire) != num_cores {
            vibrio::syscalls::Fs::read_at(fd, &mut page[0..1], 0).expect("can't read_at");
        }

        if core == *self.min_core.borrow() {
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
