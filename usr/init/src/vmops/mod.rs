// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::convert::TryInto;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use log::{error, info};
use x86::bits64::paging::{VAddr, BASE_PAGE_SIZE, PML4_SLOT_SIZE};

use lineup::tls2::{Environment, SchedulerControlBlock};

use crate::histogram;

pub mod queue;
pub mod unmaplat;

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);
static LATENCY_HISTOGRAM: spin::Mutex<Option<histogram::Histogram>> = spin::Mutex::new(None);

unsafe extern "C" fn maponly_bencher_trampoline(arg1: *mut u8) -> *mut u8 {
    let cores = arg1 as usize;
    maponly_bencher(cores);
    ptr::null_mut()
}

fn maponly_bencher(cores: usize) {
    use vibrio::syscalls::*;
    info!("Trying to allocate a frame");
    let (frame_id, _paddr) =
        PhysicalMemory::allocate_base_page().expect("Can't allocate a memory obj");
    info!("Got frame_id {:#?}", frame_id);

    let vspace_offset = lineup::tls2::Environment::tid().0 + 1;
    let mut base: u64 = (PML4_SLOT_SIZE + (PML4_SLOT_SIZE * vspace_offset)) as u64;
    info!("start mapping at {:#x}", base);

    #[cfg(feature = "latency")]
    pub const LATENCY_MEASUREMENTS: usize = 100_000;
    #[cfg(feature = "latency")]
    let mut latency: Vec<Duration> = Vec::with_capacity(LATENCY_MEASUREMENTS);

    // Synchronize with all cores
    POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
    while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
        core::hint::spin_loop();
    }

    let mut vops = 0;
    let mut iteration = 0;
    let bench_duration_secs = if cfg!(feature = "smoke") && !cfg!(feature = "latency") {
        1
    } else if cfg!(feature = "smoke") && cfg!(feature = "latency") {
        6
    } else {
        // tput
        10
    };

    'outer: while iteration <= bench_duration_secs {
        let start = rawtime::Instant::now();
        while start.elapsed().as_secs() < 1 {
            #[cfg(feature = "latency")]
            let before = rawtime::Instant::now();
            unsafe { VSpace::map_frame(frame_id, base).expect("Map syscall failed") };
            #[cfg(feature = "latency")]
            {
                // Skip 4s for warmup
                if iteration > 4 {
                    latency.push(before.elapsed());
                    if latency.len() == LATENCY_MEASUREMENTS {
                        break 'outer;
                    }
                }
            }
            vops += 1;
            base += BASE_PAGE_SIZE as u64;
        }
        #[cfg(not(feature = "latency"))]
        info!(
            "{},maponly,{},{},{},{},{}",
            Environment::scheduler().core_id,
            cores,
            4096,
            bench_duration_secs * 1000,
            iteration * 1000,
            vops
        );
        vops = 0;
        iteration += 1;
    }
    debug_assert!(vops > 0);

    #[cfg(feature = "latency")]
    {
        let mut hlock = LATENCY_HISTOGRAM.lock();
        for (_idx, duration) in latency.iter().enumerate() {
            let h = hlock.as_mut().unwrap();
            h.increment(duration.as_nanos().try_into().unwrap())
                .expect("increment histogram fail");
        }
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
                            .spawn_on_core(
                                Some(maponly_bencher_trampoline),
                                idx as *mut u8,
                                core_id,
                            )
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
            "maponly",
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
