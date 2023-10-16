use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use core::num::ParseIntError;
use core::ptr;
use core::str::FromStr;

use core::sync::atomic::{AtomicUsize, Ordering};

use log::{error, info};
use x86::bits64::paging::VAddr;

use lineup::tls2::{Environment, SchedulerControlBlock};

use md5::{Digest, Md5};

use vibrio::system::mtid_from_gtid;

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

const CHUNK_SIZE: usize = 1024;

pub struct ARGs {
    pub max_cores: usize,
    pub max_clients: usize,
}

// Hash function
// Equivalent to 1 operation
// Currently not doing anything with the hash
fn hashmem(core_id: usize, buffer: &Arc<Vec<u8>>) {
    let mtid = mtid_from_gtid(core_id);

    let offset = mtid * CHUNK_SIZE;
    let buffer: [u8; CHUNK_SIZE] = buffer[offset..offset + CHUNK_SIZE].try_into().unwrap();
    let mut hasher = Md5::new();
    hasher.update(buffer);
    let hash = hasher.finalize();
}

fn thread_routine(
    core_id: usize,
    cur_cores: usize,
    tot_cores: usize,
    buffer: &Arc<Vec<u8>>,
    time: usize,
) {
    // Synchronize all cores
    POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
    while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
        core::hint::spin_loop();
    }

    let mut ops = 0;

    let start = rawtime::Instant::now();
    while start.elapsed().as_secs() < 1 {
        for i in 0..64 {
            let _ = hashmem(core_id, buffer);
            ops += 1;
        }
    }
    info!(
        "{},memhash,{},{},{},{}",
        core_id, ops, cur_cores, tot_cores, time
    );

    // Signal that thread is complete
    POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn thread_routine_trampoline(thread_params: *mut u8) -> *mut u8 {
    let params = Arc::from_raw(thread_params as *const ThreadParams);

    let core_id = params.core_id;
    let cur_cores = params.cur_cores;
    let tot_cores = params.tot_cores;
    let buffer = &params.buffer;
    let time = params.time;
    thread_routine(core_id, cur_cores, tot_cores, buffer, time);
    ptr::null_mut()
}

struct ThreadParams {
    core_id: usize,
    cur_cores: usize,
    tot_cores: usize,
    buffer: Arc<Vec<u8>>,
    nclients: usize,
    max_clients: usize,
    time: usize,
}

pub fn bench() {
    let hwthreads = vibrio::syscalls::System::threads().expect("Cant get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;
    let cores = hwthreads.len();
    let current_core = vibrio::syscalls::System::core_id().expect("Can't get core id");
    let mut core_ids = Vec::with_capacity(cores);

    // Allocate memory region and populate it
    let mut mem_region: Vec<u8> = vec![0; cores * CHUNK_SIZE];
    for i in 0..cores * CHUNK_SIZE {
        mem_region[i] = (i % 256) as u8;
    }
    let mem_region: Arc<Vec<u8>> = Arc::new(mem_region);

    let mut time = 1;

    // increment cores first, then decrement
    for i in 0..2 {
        // let hwthreads_copy = hwthreads.clone();
        for hwthread in hwthreads.iter().take(cores) {
            while POOR_MANS_BARRIER.load(Ordering::Relaxed) != core_ids.len() {
                core::hint::spin_loop();
            }

            // incrementing cores
            if i == 0 {
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
            } else {
                // free core from program when decrementing
                let cid = core_ids.pop().unwrap();
                // vibrio::syscalls::Process::release_core(cid).expect("Cannot release core!");
            }

            // info!("Running memhash benchmark with cores: {:?}", core_ids);

            let cores_in_use = core_ids.len();
            let core_ids_copy = core_ids.clone();
            let buffer_ptr = mem_region.clone();

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
                            tot_cores: cores.clone(),
                            buffer: buffer_ptr.clone(),
                            nclients: 1,
                            max_clients: 1, //PLACEHOLDER
                            time: time.clone(),
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
            time += 1;
        }
    }
}
