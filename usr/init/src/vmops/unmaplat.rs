// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use lazy_static::lazy_static;
use log::{error, info};
use x86::bits64::paging::{VAddr, BASE_PAGE_SIZE};

use lineup::tls2::{Environment, SchedulerControlBlock};

use super::queue::{Queue, QueueSender};

use crate::histogram;

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);
static EXIT: AtomicBool = AtomicBool::new(false);
static LATENCY_HISTOGRAM: spin::Mutex<Option<histogram::Histogram>> = spin::Mutex::new(None);

#[derive(Debug)]
enum Cmd {}

lazy_static! {
    static ref TX_CHANNELS: spin::Mutex<Vec<Option<QueueSender<Cmd>>>> = {
        let cpus = vibrio::syscalls::System::threads().map(|t| t.len()).unwrap_or(28);
        spin::Mutex::new(vec![None; cpus+1]) // +1 because thread id starts at 1
    };
}

unsafe extern "C" fn unmap_bencher_trampoline(arg1: *mut u8) -> *mut u8 {
    let cores = arg1 as usize;
    unmap_bencher(cores);
    ptr::null_mut()
}

fn unmap_bencher(_cores: usize) {
    use vibrio::syscalls::*;

    let thread_id = lineup::tls2::Environment::tid().0;
    let base: u64 = 0x0510_0000_0000;

    let frame_id = if thread_id == 1 {
        let (frame_id, paddr) =
            PhysicalMemory::allocate_base_page().expect("Can't allocate a memory obj");
        info!("Mapping frame#{} {:#x} -> {:#x}", frame_id, base, paddr);
        frame_id
    } else {
        404
    };

    pub const LATENCY_MEASUREMENTS: usize = 100_000;
    let mut initiator_latency: Vec<u64> = Vec::with_capacity(LATENCY_MEASUREMENTS);
    let _responder_latency: Vec<u64> = Vec::with_capacity(LATENCY_MEASUREMENTS);

    let _rx_cmd = {
        let (tx, rx) = Queue::unbounded();
        TX_CHANNELS.lock()[thread_id].replace(tx);
        rx
    };

    let _bench_duration_secs = if cfg!(feature = "smoke") && !cfg!(feature = "latency") {
        1
    } else if cfg!(feature = "smoke") && cfg!(feature = "latency") {
        // dont measure that long for latency
        25
    } else {
        // tput measurements
        10
    };

    // Synchronize with all cores
    POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
    while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
        core::hint::spin_loop();
    }
    let _tx_master = TX_CHANNELS.lock()[1].as_ref().unwrap().clone();

    for _idx in 0..LATENCY_MEASUREMENTS {
        if thread_id == 1 {
            unsafe {
                VSpace::map_frame(frame_id, base).expect("Map syscall failed");
            }
        } else {
            while !EXIT.load(Ordering::Relaxed) {}
            break;
        }

        if thread_id == 1 {
            unsafe {
                let unmap_start = x86::time::rdtsc();
                VSpace::unmap(base, BASE_PAGE_SIZE as u64).expect("Unmap syscall failed");
                let unmap_end = x86::time::rdtsc();
                initiator_latency.push(unmap_end - unmap_start);
            }
        } else {
            // repeat...
        }
    }

    if thread_id == 1 {
        EXIT.store(true, Ordering::Relaxed);

        let mut hlock = LATENCY_HISTOGRAM.lock();
        for (_idx, duration) in initiator_latency.iter().enumerate() {
            let h = hlock.as_mut().unwrap();
            h.increment(*duration).expect("can't increment histogram");
        }
    } else {
        vibrio::syscalls::System::stats().expect("can't get stats");
    }

    POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
}

pub fn bench(ncores: Option<usize>) {
    info!("thread_id,benchmark,core,ncores,memsize,duration_total,duration,operations");

    LATENCY_HISTOGRAM
        .lock()
        .replace(histogram::Histogram::new());

    let hwthreads = vibrio::syscalls::System::threads().expect("Can't get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;
    let cores = ncores.unwrap_or(hwthreads.len());

    let mut maximum = 1; // We already have core 0
    for hwthread in hwthreads.iter().take(cores) {
        if hwthread.id != 0 {
            match vibrio::syscalls::Process::request_core(
                hwthread.id,
                VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
            ) {
                Ok(_) => {
                    maximum += 1;
                    continue;
                }
                Err(e) => {
                    error!("Can't spawn on {:?}: {:?}", hwthread.id, e);
                    break;
                }
            }
        }
    }
    info!("Spawned {} cores", maximum);

    s.spawn(
        32 * 4096,
        move |_| {
            // use `for idx in 1..maximum+1` to run over all cores
            // currently we'll run out of 4 KiB frames
            for idx in maximum..maximum + 1 {
                let mut thandles = Vec::with_capacity(idx);
                // Set up barrier
                POOR_MANS_BARRIER.store(idx, Ordering::SeqCst);

                for core_id in 0..idx {
                    thandles.push(
                        Environment::thread()
                            .spawn_on_core(Some(unmap_bencher_trampoline), idx as *mut u8, core_id)
                            .expect("Can't spawn bench thread?"),
                    );
                }

                for thandle in thandles {
                    Environment::thread().join(thandle);
                }
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    while s.has_active_threads() {
        s.run(&scb);
    }

    #[cfg(feature = "latency")]
    {
        let hlock = LATENCY_HISTOGRAM.lock();
        let h = hlock.as_ref().unwrap();

        info!("benchmark,ncores,memsize,p1,p25,p50,p75,p99,p99.9,p100");
        // Don't adjust this line without changing `s10_vmops_latency_benchmark`
        info!(
            "Latency percentiles: {},{},{},{},{},{},{},{},{},{}",
            "unmap",
            cores,
            4096,
            h.percentile(1.0).unwrap(),
            h.percentile(25.0).unwrap(),
            h.percentile(50.0).unwrap(),
            h.percentile(75.0).unwrap(),
            h.percentile(99.0).unwrap(),
            h.percentile(99.9).unwrap(),
            h.percentile(100.0).unwrap(),
        );
    }
}
