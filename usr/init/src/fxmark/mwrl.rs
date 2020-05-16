use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::{format, vec, vec::Vec};
use core::cell::RefCell;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use vibrio::io::*;

#[derive(Clone, Default)]
pub struct MWRL {}

impl Bench for MWRL {
    fn init(&self, cores: Vec<usize>) {
        unsafe {
            for core in cores {
                let file_name = format!("/{}/file-0.txt\0", core);
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

    fn run(&self, POOR_MANS_BARRIER: &AtomicUsize, duration: u64, core: usize) -> Vec<usize> {
        use vibrio::io::*;
        use vibrio::syscalls::*;
        let mut iops_per_second = Vec::with_capacity(duration as usize);

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Release);
        while POOR_MANS_BARRIER.load(Ordering::Acquire) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let mut iops = 0;
        let mut iterations = 0;
        let mut iter = 0;
        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for i in 0..64 {
                    let old_name = format!("/{}/file-{}.txt\0", core, iter);
                    iter += 1;
                    let new_name = format!("/{}/file-{}.txt\0", core, iter);
                    // Rename the file
                    if vibrio::syscalls::Fs::rename(
                        old_name.as_ptr() as u64,
                        new_name.as_ptr() as u64,
                    )
                    .expect("FileRename syscall failed")
                        != 0
                    {
                        panic!("FileRename syscall failed");
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

unsafe impl Sync for MWRL {}
