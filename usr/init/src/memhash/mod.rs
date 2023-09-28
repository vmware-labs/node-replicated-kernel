use alloc::vec::Vec;

use core::sync::atomic::AtomicUsize;

use log::{error, info};
use x86::bits64::paging::VAddr;

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

// Hash function
// Equivalent to 1 operation
fn hashmem() -> u64 {
    0
}

pub fn bench(ncores: Option<usize>) {

    let hwthreads = vibrio::syscalls::System::threads().expect("Cant get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;
    let cores = ncores.unwrap_or(hwthreads.len());
    let current_core = vibrio::syscalls::System::core_id().expect("Can't get core id");
    let mut core_ids = Vec::with_capacity(cores);

    for hwthread in hwthreads.iter().take(cores) {
        if hwthread.id != current_core {
            match vibrio::syscalls::Process::request_core(
                hwthread.id,
                VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
            ) {
                Ok(core_token) => {
                    core_ids.push(core_token.gtid());
                    // continue;
                }
                Err(e) => {
                    error!("Can't spawn on {:?}: {:?}", hwthread.id, e);
                    break;
                }
            }
        } else {
            core_ids.push(hwthread.id);
        }
        info!("core_ids: {:?}", core_ids);
    }
}
