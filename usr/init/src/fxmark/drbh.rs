// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use vibrio::io::*;

#[derive(Clone)]
pub struct DRBH {
    page: Vec<u8>,
}

impl Default for DRBH {
    fn default() -> DRBH {
        let page = vec![0xb; PAGE_SIZE as usize];
        DRBH { page }
    }
}

impl Bench for DRBH {
    fn init(&self, _cores: Vec<usize>, _open_files: usize) {
        // Open a shared file for each core.
        let fd = vibrio::syscalls::Fs::open(
            "file.txt",
            FileFlags::O_RDWR | FileFlags::O_CREAT,
            FileModes::S_IRWXU,
        )
        .expect("FileOpen syscall failed");

        // Write a single page to the file at offset 0.
        let ret =
            vibrio::syscalls::Fs::write_at(fd, &self.page, 0).expect("FileWriteAt syscall failed");
        assert_eq!(ret, PAGE_SIZE as u64);

        vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
    }

    fn run(
        &self,
        poor_mans_barrier: &AtomicUsize,
        duration: u64,
        _core: usize,
        _write_ratio: usize,
    ) -> Vec<usize> {
        use vibrio::io::*;
        let mut iops_per_second = Vec::with_capacity(duration as usize);

        // Load fd from a shared struct.
        let fd = vibrio::syscalls::Fs::open(
            "file.txt",
            FileFlags::O_RDWR | FileFlags::O_CREAT,
            FileModes::S_IRWXU,
        )
        .expect("FileOpen syscall failed");
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
                    // Read a page from the shared file at offset 0.
                    if vibrio::syscalls::Fs::read_at(fd, page, 0)
                        .expect("FileReadAt syscall failed")
                        != PAGE_SIZE
                    {
                        panic!("DRBH: read_at() failed");
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

unsafe impl Sync for DRBH {}
