// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::RefCell;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use vibrio::io::*;

#[derive(Clone)]
pub struct DWOM {
    page: Vec<u8>,
}

impl Default for DWOM {
    fn default() -> DWOM {
        let base: u64 = 0xff000;
        let size: u64 = 0x1000;
        // Allocate a buffer and write data into it, which is later written to the file.
        let page = unsafe {
            vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");
            from_raw_parts_mut(base as *mut u8, size as usize)
        }
        .to_vec();

        DWOM { page }
    }
}

impl Bench for DWOM {
    fn init(&self, cores: Vec<usize>, _open_files: usize) {
        unsafe {
            let fd = vibrio::syscalls::Fs::open(
                "file.txt\0".as_ptr() as u64,
                u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
                u64::from(FileModes::S_IRWXU),
            )
            .expect("FileOpen syscall failed");

            let mut offset = 0;
            for _core in cores.iter() {
                if vibrio::syscalls::Fs::write_at(fd, self.page.as_ptr() as u64, 4096, offset)
                    .expect("FileWriteAt syscall failed")
                    != 4096
                {
                    panic!("FileWriteAt syscall failed");
                }
            }
            if vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed") != 0 {
                panic!("FileClose syscall failed");
            };
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
        let fd = vibrio::syscalls::Fs::open(
            "file.txt\0".as_ptr() as u64,
            u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
            u64::from(FileModes::S_IRWXU),
        )
        .expect("FileOpen syscall failed");
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let size: u64 = 0x1000;
        let base: u64 = 0xff0000 + (size * core as u64);
        // Allocate a buffer and write data into it, which is later written to the file.
        let mut page: &mut [u8] = unsafe {
            vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");
            from_raw_parts_mut(base as *mut u8, size as usize)
        };

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
                    if vibrio::syscalls::Fs::write_at(
                        fd,
                        page.as_ptr() as u64,
                        PAGE_SIZE,
                        core as i64 * 4096,
                    )
                    .expect("FileWriteAt syscall failed")
                        != PAGE_SIZE
                    {
                        panic!("DWOM: write_at() failed");
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

unsafe impl Sync for DWOM {}
