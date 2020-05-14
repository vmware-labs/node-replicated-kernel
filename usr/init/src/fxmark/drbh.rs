use crate::fxmark::Bench;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use log::info;

#[derive(Clone)]
pub struct DRBH {}

impl Default for DRBH {
    fn default() -> DRBH {
        DRBH {}
    }
}

impl Bench for DRBH {
    fn init(&self, cores: Vec<usize>) {
        info!("{:?}", cores);
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
        while iterations <= duration {
            let start = rawtime::Instant::now();
            while start.elapsed().as_secs() < 1 {
                for i in 0..64 {
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
