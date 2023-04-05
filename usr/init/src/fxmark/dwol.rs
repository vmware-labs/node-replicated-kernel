// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::RefCell;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use lineup::core_id_to_index;
use vibrio::io::*;

#[derive(Clone)]
pub struct DWOL {
    page: Vec<u8>,
    fds: RefCell<Vec<u64>>,
    cores: RefCell<usize>,
}

impl Default for DWOL {
    fn default() -> DWOL {
        let base: u64 = 0xff000;
        let size: u64 = 0x1000;
        // Allocate a buffer and write data into it, which is later written to the file.
        let page = unsafe {
            vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");
            from_raw_parts_mut(base as *mut u8, size as usize)
        }
        .to_vec();
        let fd = vec![u64::MAX; 512];
        DWOL {
            page,
            fds: RefCell::new(fd),
            cores: RefCell::new(0),
        }
    }
}

impl Bench for DWOL {
    fn init(&self, cores: Vec<usize>, _open_files: usize) {
        *self.cores.borrow_mut() = cores.len();
        for core in cores {
            let fd = vibrio::syscalls::Fs::open(
                format!("file{}.txt", core),
                FileFlags::O_RDWR | FileFlags::O_CREAT,
                FileModes::S_IRWXU,
            )
            .expect("FileOpen syscall failed");

            let ret = vibrio::syscalls::Fs::write_at(fd, &self.page, 0)
                .expect("FileWriteAt syscall failed");
            assert_eq!(ret, PAGE_SIZE as u64);
            self.fds.borrow_mut()[core_id_to_index(core)] = fd;
        }
    }

    fn run(
        &self,
        poor_mans_barrier: &AtomicUsize,
        duration: u64,
        core: usize,
        _write_ratio: usize,
    ) -> Vec<usize> {
        let mut iops_per_second = Vec::with_capacity(duration as usize);
        let core_index = core_id_to_index(core);
        let fd = self.fds.borrow()[core_index];
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let size: u64 = 0x1000;
        let base: u64 = 0xff0000 + (size * core_index as u64);
        // Allocate a buffer and write data into it, which is later written to the file.
        let page: &mut [u8] = unsafe {
            vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");
            from_raw_parts_mut(base as *mut u8, size as usize)
        };

        // Synchronize with all cores
        poor_mans_barrier.fetch_sub(1, Ordering::Release);
        while poor_mans_barrier.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }

        let mut iops = 0;
        let mut iterations = 0;
        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for _i in 0..64 {
                    if vibrio::syscalls::Fs::write_at(fd, page, 0)
                        .expect("FileWriteAt syscall failed")
                        != PAGE_SIZE
                    {
                        panic!("DWOL: write_at() failed");
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

        iops_per_second.clone()
    }
}

unsafe impl Sync for DWOL {}
