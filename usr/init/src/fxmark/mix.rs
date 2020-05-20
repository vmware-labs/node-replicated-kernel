use crate::fxmark::{Bench, PAGE_SIZE};
use alloc::{format, vec, vec::Vec};
use core::cell::RefCell;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use vibrio::io::*;
use x86::random::rdrand16;

#[derive(Clone)]
pub struct MIX {
    page: Vec<u8>,
    fd: RefCell<u64>,
    size: i64,
    total_cores: RefCell<usize>,
}

impl Default for MIX {
    fn default() -> MIX {
        let base: u64 = 0xff000;
        let size: u64 = 0x1000;
        // Allocate a buffer and write data into it, which is later written to the file.
        let page = unsafe {
            vibrio::syscalls::VSpace::map(base, size).expect("Map syscall failed");
            from_raw_parts_mut(base as *mut u8, size as usize)
        }
        .to_vec();

        MIX {
            page,
            fd: RefCell::new(u64::MAX),
            size: 128 * 1024 * 1024,
            total_cores: RefCell::new(0),
        }
    }
}

impl Bench for MIX {
    fn init(&self, cores: Vec<usize>) {
        *self.total_cores.borrow_mut() = cores.len();
        unsafe {
            let fd = vibrio::syscalls::Fs::open(
                "file.txt\0".as_ptr() as u64,
                u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
                u64::from(FileModes::S_IRWXU),
            )
            .expect("FileOpen syscall failed");

            let ret =
                vibrio::syscalls::Fs::write_at(fd, self.page.as_ptr() as u64, PAGE_SIZE, self.size)
                    .expect("FileWriteAt syscall failed");
            assert_eq!(ret, PAGE_SIZE as u64);
            *self.fd.borrow_mut() = fd;
        }
    }

    fn run(
        &self,
        POOR_MANS_BARRIER: &AtomicUsize,
        duration: u64,
        core: usize,
        write_ratio: usize,
    ) -> Vec<usize> {
        use vibrio::io::*;
        use vibrio::syscalls::*;
        let mut iops_per_second = Vec::with_capacity(duration as usize);
        let fd = *self.fd.borrow();
        if fd == u64::MAX {
            panic!("Unable to open a file");
        }
        let total_cores = *self.total_cores.borrow();
        let total_pages: usize = self.size as usize / 4096;
        let pages_per_core = total_pages / total_cores;
        let lower;
        if core == 0 {
            lower = 0;
        } else {
            lower = (core - 1) * pages_per_core;
        }
        let higher = core * pages_per_core;

        let page: &mut [i8; PAGE_SIZE as usize] = &mut [0; PAGE_SIZE as usize];

        // Synchronize with all cores
        POOR_MANS_BARRIER.fetch_sub(1, Ordering::Release);
        while POOR_MANS_BARRIER.load(Ordering::Acquire) != 0 {
            core::sync::atomic::spin_loop_hint();
        }

        let mut iops = 0;
        let mut iterations = 0;
        let mut random_num: u16 = 0;

        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for i in 0..64 {
                    unsafe { rdrand16(&mut random_num) };
                    let rand = lower + (random_num as usize % pages_per_core);
                    let offset = rand * 4096;

                    if random_num as usize % 100 < write_ratio {
                        if vibrio::syscalls::Fs::write_at(
                            fd,
                            page.as_ptr() as u64,
                            PAGE_SIZE,
                            offset as i64,
                        )
                        .expect("FileWriteAt syscall failed")
                            != PAGE_SIZE
                        {
                            panic!("MIX: write_at() failed");
                        }
                    } else {
                        if vibrio::syscalls::Fs::read_at(
                            fd,
                            page.as_ptr() as u64,
                            PAGE_SIZE,
                            offset as i64,
                        )
                        .expect("FileReadAt syscall failed")
                            != PAGE_SIZE
                        {
                            panic!("MIX: read_at() failed");
                        }
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

unsafe impl Sync for MIX {}
