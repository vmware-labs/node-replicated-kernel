use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use log::{error, info};
use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE};

use lineup::threads::ThreadId;
use lineup::tls2::{Environment, SchedulerControlBlock};

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn maponly_bencher_trampoline(arg1: *mut u8) -> *mut u8 {
    let cores = arg1 as usize;
    maponly_bencher(cores);
    ptr::null_mut()
}

fn maponly_bencher(cores: usize) {
    use vibrio::io::*;
    use vibrio::syscalls::*;
    info!("Trying to allocate a frame");
    let (frame_id, paddr) =
        PhysicalMemory::allocate_base_page().expect("Can't allocate a memory obj");
    info!("Got frame_id {:#?}", frame_id);

    let vspace_offset = lineup::tls2::Environment::tid().0 + 1;
    let mut base: u64 = (0x0f10_0000_0000 + (0x66_0000_0000 * vspace_offset) as u64);
    let size: u64 = BASE_PAGE_SIZE as u64;
    info!("start mapping at {:#x}", base);

    // Synchronize with all cores
    POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
    while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
        core::sync::atomic::spin_loop_hint();
    }

    let mut vops = 0;
    let mut iteration = 0;
    while iteration <= 10 {
        let start = rawtime::Instant::now();
        while start.elapsed().as_secs() < 1 {
            unsafe { VSpace::map_frame(frame_id, base).expect("Map syscall failed") };
            vops += 1;
            base += BASE_PAGE_SIZE as u64;
        }
        info!(
            "{},maponly,{},{},{},{},{}",
            Environment::scheduler().core_id,
            cores,
            4096,
            10000,
            iteration * 1000,
            vops
        );
        vops = 0;
        iteration += 1;
    }

    POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
}

pub fn bench() {
    info!("thread_id,benchmark,core,ncores,memsize,duration_total,duration,operations");

    let hwthreads = vibrio::syscalls::System::threads().expect("Can't get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;

    let mut maximum = 1; // We already have core 0
    for hwthread in hwthreads.iter() {
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
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    while s.has_active_threads() {
        s.run(&scb);
    }
}
