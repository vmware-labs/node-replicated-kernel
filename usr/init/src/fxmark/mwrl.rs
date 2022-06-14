// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::Bench;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use vibrio::io::*;

#[derive(Clone, Default)]
pub struct MWRL {}

impl Bench for MWRL {
    fn init(&self, cores: Vec<usize>, _open_files: usize) {
        for core in cores {
            let fd = vibrio::syscalls::Fs::open(
                format!("/{}/file-0.txt", core),
                FileFlags::O_RDWR | FileFlags::O_CREAT,
                FileModes::S_IRWXU,
            )
            .expect("FileOpen syscall failed");

            // Close the file.
            vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
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

        // Synchronize with all cores
        poor_mans_barrier.fetch_sub(1, Ordering::Release);
        while poor_mans_barrier.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }

        let mut iops = 0;
        let mut iterations = 0;
        let mut iter = 0;
        let filenames = vec![
            format!("/{}/file-{}.txt", core, 0),
            format!("/{}/file-{}.txt", core, 1),
        ];
        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for _i in 0..64 {
                    let old_name = iter % 2;
                    iter += 1;
                    let new_name = iter % 2;
                    // Rename the file
                    vibrio::syscalls::Fs::rename(
                        filenames[old_name].as_str(),
                        filenames[new_name].as_str(),
                    )
                    .expect("FileRename syscall failed");
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

unsafe impl Sync for MWRL {}
