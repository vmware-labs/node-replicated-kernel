// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use kpi::process::MAX_CORES;
use lineup::core_id_to_index;
use vibrio::io::*;

#[derive(Clone)]
pub struct DRBL {
    page: Vec<u8>,
    fds: RefCell<Vec<u64>>,
}

impl Default for DRBL {
    fn default() -> DRBL {
        let page = vec![0xb; PAGE_SIZE as usize];
        let fd = vec![u64::MAX; MAX_CORES];
        DRBL {
            page,
            fds: RefCell::new(fd),
        }
    }
}

impl Bench for DRBL {
    fn init(&self, cores: Vec<usize>, _open_files: usize) {
        for core in cores {
            let fd = vibrio::syscalls::Fs::open(
                format!("file{}.txt", core),
                FileFlags::O_RDWR | FileFlags::O_CREAT,
                FileModes::S_IRWXU,
            )
            .expect("FileOpen syscall failed");

            // This call is to tests nrk memory deallocator for large allocations.
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
        let fd = self.fds.borrow()[core_id_to_index(core)];
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let page: &mut [u8; PAGE_SIZE as usize] = &mut [0; PAGE_SIZE as usize];

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
                    if vibrio::syscalls::Fs::read_at(fd, page, 0)
                        .expect("FileReadAt syscall failed")
                        != PAGE_SIZE
                    {
                        panic!("DRBL: read_at() failed");
                    }
                    iops += 1;
                }
            }
            iops_per_second.push(iops);
            iterations += 1;
            iops = 0;
        }

        poor_mans_barrier.fetch_add(1, Ordering::Relaxed);
        iops_per_second.clone()
    }
}

unsafe impl Sync for DRBL {}
