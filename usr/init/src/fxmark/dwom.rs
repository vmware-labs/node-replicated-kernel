// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::vec::Vec;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use lineup::core_id_to_index;
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
        let fd = vibrio::syscalls::Fs::open(
            "file.txt",
            FileFlags::O_RDWR | FileFlags::O_CREAT,
            FileModes::S_IRWXU,
        )
        .expect("FileOpen syscall failed");

        let offset = 0;
        for _core in cores.iter() {
            if vibrio::syscalls::Fs::write_at(fd, &self.page, offset)
                .expect("FileWriteAt syscall failed")
                != 4096
            {
                panic!("FileWriteAt syscall failed");
            }
        }
        vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
    }

    fn run(
        &self,
        poor_mans_barrier: &AtomicUsize,
        duration: u64,
        core: usize,
        _write_ratio: usize,
    ) -> Vec<usize> {
        use vibrio::io::*;
        let mut iops_per_second = Vec::with_capacity(duration as usize);
        let fd = vibrio::syscalls::Fs::open(
            "file.txt",
            FileFlags::O_RDWR | FileFlags::O_CREAT,
            FileModes::S_IRWXU,
        )
        .expect("FileOpen syscall failed");
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let size: u64 = 0x1000;
        let base: u64 = 0xff0000 + (size * core_id_to_index(core) as u64);
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
                    if vibrio::syscalls::Fs::write_at(
                        fd,
                        page,
                        core_id_to_index(core) as i64 * 4096,
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

        poor_mans_barrier.fetch_add(1, Ordering::Relaxed);
        iops_per_second.clone()
    }
}

unsafe impl Sync for DWOM {}
