use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;

use core::sync::atomic::{AtomicUsize, Ordering};

use log::{error, info};
use x86::bits64::paging::VAddr;

use lineup::tls2::{Environment, SchedulerControlBlock};

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

// Hash function
// Equivalent to 1 operation
fn hashmem(core_id: usize) -> u64 {
    0
}

fn thread_routine(core_id: usize, cur_cores: usize, tot_cores: usize) {
    // Synchronize all cores
    POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
    while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
        core::hint::spin_loop();
    }

    let mut ops = 0;

    let start = rawtime::Instant::now();
    while start.elapsed().as_secs() < 1 {
        let _ = hashmem(core_id);
        ops += 1
    }
    info!("{},memhash,{},{},{}", core_id, ops, cur_cores, tot_cores);
}

unsafe extern "C" fn thread_routine_trampoline(thread_params: *mut u8) -> *mut u8 {
    let params = Arc::from_raw(thread_params as *const ThreadParams);

    let core_id = params.core_id;
    let cur_cores = params.cur_cores;
    let tot_cores = params.tot_cores;
    thread_routine(core_id, cur_cores, tot_cores);
    ptr::null_mut()
}

struct ThreadParams {
    core_id: usize,
    cur_cores: usize,
    tot_cores: usize,
}

pub fn bench(ncores: Option<usize>) {
    let hwthreads = vibrio::syscalls::System::threads().expect("Cant get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;
    let cores = ncores.unwrap_or(hwthreads.len());
    let current_core = vibrio::syscalls::System::core_id().expect("Can't get core id");
    let mut core_ids = Vec::with_capacity(cores);

    for hwthread in hwthreads.iter().take(cores) {
        // Reserve next core
        if hwthread.id != current_core {
            match vibrio::syscalls::Process::request_core(
                hwthread.id,
                VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
            ) {
                Ok(core_token) => {
                    core_ids.push(core_token.gtid());
                }
                Err(e) => {
                    error!("Can't spawn on {:?}: {:?}", hwthread.id, e);
                    break;
                }
            }
        } else {
            core_ids.push(hwthread.id);
        }

        // info!("Running memhash benchmark with cores: {:?}", core_ids);

        let cores_in_use = core_ids.len();
        let core_ids_copy = core_ids.clone();

        // Spawn threads
        s.spawn(
            32 * 4096, // stack size, not sure how much to allocate here
            move |_| {
                let mut thandles = Vec::with_capacity(cores_in_use.clone());
                POOR_MANS_BARRIER.store(cores_in_use.clone(), Ordering::SeqCst);

                for core_id in core_ids_copy {
                    let params = ThreadParams {
                        core_id: core_id,
                        cur_cores: cores_in_use.clone(),
                        tot_cores: ncores.unwrap().clone(),
                    };

                    thandles.push(
                        Environment::thread()
                            .spawn_on_core(
                                Some(thread_routine_trampoline),
                                Arc::into_raw(params.into()) as *const _ as *mut u8,
                                core_id,
                            )
                            .expect("Can't spawn bench thread"),
                    );
                }
            },
            ptr::null_mut(),
            current_core,
            None,
        );
        let scb: SchedulerControlBlock = SchedulerControlBlock::new(current_core);
        while s.has_active_threads() {
            s.run(&scb);
        }
    }
}
