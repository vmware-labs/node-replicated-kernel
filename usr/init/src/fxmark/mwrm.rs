use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::{format, vec, vec::Vec};
use core::cell::RefCell;
use core::convert::TryInto;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use log::info;
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
            // TODO: If we increase the total file > 10_000, bespin throws the error like:
            // Got a large allocation Layout { size_: 3211496, align_: 8 }, need bp 273 lp 1
            total_files: 10_000,
            total_cores: RefCell::new(0),
        }
    }
}

impl Bench for MWRM {
    fn init(&self, cores: Vec<usize>) {
        let core_nums = cores.len();
        *self.total_cores.borrow_mut() = core_nums;
        let files_per_core = self.total_files / core_nums;
        unsafe {
            for core in cores {
                for iter in 0..files_per_core {
                    let file_name = format!("/{}/file-{}-{}.txt\0", core, core, iter);
                    let fd = vibrio::syscalls::Fs::open(
                        file_name.as_ptr() as u64,
                        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
                        u64::from(FileModes::S_IRWXU),
                    )
                    .expect("FileOpen syscall failed");

                    // Close the file.
                    let ret = vibrio::syscalls::Fs::close(fd).expect("FileClose syscall failed");
                    assert_eq!(ret, 0);
                }
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
        let core_nums = *self.total_cores.borrow();
        let files_per_core = self.total_files / core_nums;
        let mut iops = 0;

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Release);
        while POOR_MANS_BARRIER.load(Ordering::Acquire) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let start = Instant::now();
        for iter in 0..files_per_core {
            let old_name = format!("/{}/file-{}-{}.txt\0", core, core, iter);
            let new_name = format!("/fxmark/file-{}-{}.txt\0", core, iter);
            if vibrio::syscalls::Fs::rename(old_name.as_ptr() as u64, new_name.as_ptr() as u64)
                .expect("FileRename syscall failed")
                != 0
            {
                panic!("FileRename syscall failed");
            }
            iops += 1;
        }
        let stop = Instant::now();
        let throughput = calculate_throughput(iops, stop - start);

        // Just to avoid changing the throughput reporting code
        // which expects `duration` number of readings.
        for _i in 0..duration + 1 {
            iops_per_second.push(throughput);
        }
        POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
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
