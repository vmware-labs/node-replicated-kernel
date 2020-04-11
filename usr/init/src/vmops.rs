use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use log::{error, info};
use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE};

use lineup::threads::ThreadId;
use lineup::tls2::{Environment, SchedulerControlBlock};

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

fn maponly_bencher(cores: usize) {
    use vibrio::io::*;
    use vibrio::syscalls::*;

    let (frame_id, paddr) =
        PhysicalMemory::allocate_base_page().expect("Can't allocate a memory obj");
    info!("Got frame_id {:#?}", frame_id);

    let vspace_offset = lineup::tls2::Environment::tid().0 + 1;
    let mut base: u64 = (0x1200_0000_0000 * vspace_offset as u64) + 0xdeef_f000;
    let size: u64 = BASE_PAGE_SIZE as u64;
    info!("start mapping at {:#x}", base);

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
            "{},maponly,{},{},{},{},{},{}",
            Environment::tid().0,
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

    POOR_MANS_BARRIER.store(maximum, Ordering::SeqCst);

    for hwthread in hwthreads.iter().take(maximum) {
        s.spawn(
            32 * 4096,
            move |_| {
                POOR_MANS_BARRIER.fetch_sub(1, Ordering::Relaxed);
                while POOR_MANS_BARRIER.load(Ordering::Relaxed) != 0 {
                    core::sync::atomic::spin_loop_hint();
                }

                maponly_bencher(maximum);

                POOR_MANS_BARRIER.fetch_add(1, Ordering::Relaxed);
            },
            ptr::null_mut(),
            hwthread.id,
        );
    }

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    loop {
        s.run(&scb);
    }
}
