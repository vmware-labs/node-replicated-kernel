use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::{format, vec, vec::Vec};
use core::cell::RefCell;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use vibrio::io::*;

#[derive(Clone)]
pub struct DWOL {
    page: Vec<u8>,
    fds: RefCell<Vec<u64>>,
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
        }
    }
}

impl Bench for DWOL {
    fn init(&self, cores: Vec<usize>) {
        unsafe {
            for core in cores {
                let file_name = format!("file{}.txt\0", core);
                let fd = vibrio::syscalls::Fs::open(
                    file_name.as_ptr() as u64,
                    u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
                    u64::from(FileModes::S_IRWXU),
                )
                .expect("FileOpen syscall failed");

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
                    if vibrio::syscalls::Fs::write_at(fd, page.as_ptr() as u64, PAGE_SIZE, 0)
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

        POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
        iops_per_second.clone()
    }
}

unsafe impl Sync for DWOL {}
