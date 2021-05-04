// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use vibrio::io::*;

#[derive(Clone)]
pub struct DRBL {
    page: Vec<u8>,
    fds: RefCell<Vec<u64>>,
}

impl Default for DRBL {
    fn default() -> DRBL {
        let page = vec![0xb; PAGE_SIZE as usize];
        let fd = vec![u64::MAX; 512];
        DRBL {
            page,
            fds: RefCell::new(fd),
        }
    }
}

impl Bench for DRBL {
    fn init(&self, cores: Vec<usize>, _open_files: usize) {
        unsafe {
            for core in cores {
                let file_name = format!("file{}.txt\0", core);
                let fd = vibrio::syscalls::Fs::open(
                    file_name.as_ptr() as u64,
                    u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
                    u64::from(FileModes::S_IRWXU),
                )
                .expect("FileOpen syscall failed");

                // This call is to tests nrk memory deallocator for large allocations.
                let ret =
                    vibrio::syscalls::Fs::write_at(fd, self.page.as_ptr() as u64, PAGE_SIZE, 0)
                        .expect("FileWriteAt syscall failed");
                assert_eq!(ret, PAGE_SIZE as u64);
                self.fds.borrow_mut()[core as usize] = fd;
            }
        }
    }

    fn run(
        &self,
        POOR_MANS_BARRIER: &AtomicUsize,
        duration: u64,
        core: usize,
        _write_ratio: usize,
    ) -> Vec<usize> {
        use vibrio::io::*;
        use vibrio::syscalls::*;
        let mut iops_per_second = Vec::with_capacity(duration as usize);
        let fd = self.fds.borrow()[core as usize];
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let page: &mut [i8; PAGE_SIZE as usize] = &mut [0; PAGE_SIZE as usize];

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Release);
        while POOR_MANS_BARRIER.load(Ordering::Acquire) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let mut iops = 0;
        let mut iterations = 0;
        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for i in 0..64 {
                    if vibrio::syscalls::Fs::read_at(fd, page.as_ptr() as u64, PAGE_SIZE, 0)
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

        POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
        iops_per_second.clone()
    }
}

unsafe impl Sync for DRBL {}
