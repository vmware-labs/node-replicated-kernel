// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::fxmark::Bench;
use alloc::format;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::TryInto;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use rawtime::Instant;
use vibrio::io::*;

#[derive(Clone)]
pub struct MWRM {
    total_files: usize,
    total_cores: RefCell<usize>,
}

impl Default for MWRM {
    fn default() -> MWRM {
        MWRM {
            // TODO: If we increase the total file > 10_000, nrk throws the error like:
            // Got a large allocation Layout { size_: 3211496, align_: 8 }, need bp 273 lp 1
            total_files: 10_000,
            total_cores: RefCell::new(0),
        }
    }
}

impl Bench for MWRM {
    fn init(&self, cores: Vec<usize>, _open_files: usize) {
        let core_nums = cores.len();
        *self.total_cores.borrow_mut() = core_nums;
        let files_per_core = self.total_files / core_nums;
        for core in cores {
            for iter in 0..files_per_core {
                let fd = vibrio::syscalls::Fs::open(
                    format!("/{}/file-{}-{}.txt", core, core, iter),
                    FileFlags::O_RDWR | FileFlags::O_CREAT,
                    FileModes::S_IRWXU,
                )
                .expect("FileOpen syscall failed");

                // Close the file.
                vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
            }
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
        let core_nums = *self.total_cores.borrow();
        let files_per_core = self.total_files / core_nums;
        let mut iops = 0;

        // Synchronize with all cores
        poor_mans_barrier.fetch_sub(1, Ordering::Release);
        while poor_mans_barrier.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }

        let start = Instant::now();
        for iter in 0..files_per_core {
            let old_name = format!("/{}/file-{}-{}.txt", core, core, iter);
            let new_name = format!("/fxmark/file-{}-{}.txt", core, iter);
            vibrio::syscalls::Fs::rename(old_name, new_name).expect("FileRename syscall failed");
            iops += 1;
        }
        let stop = Instant::now();
        let throughput = calculate_throughput(iops, stop - start);

        // Just to avoid changing the throughput reporting code
        // which expects `duration` number of readings.
        for _i in 0..duration + 1 {
            iops_per_second.push(throughput);
        }
        poor_mans_barrier.fetch_add(1, Ordering::Relaxed);
        iops_per_second.clone()
    }
}

pub fn calculate_throughput(ops: u64, time: Duration) -> usize {
    let nano_duration = time.as_nanos();
    let nano_per_operation = nano_duration / ops as u128;
    (Duration::from_secs(1).as_nanos() / nano_per_operation)
        .try_into()
        .unwrap()
}

unsafe impl Sync for MWRM {}
