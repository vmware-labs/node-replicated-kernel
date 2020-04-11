use core::ptr;

use log::{error, info};
use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE};

use lineup::threads::ThreadId;
use lineup::tls2::{Environment, SchedulerControlBlock};

fn maponly_bencher() {
    use vibrio::io::*;
    use vibrio::syscalls::*;

    let (frame_id, paddr) =
        PhysicalMemory::allocate_base_page().expect("Can't allocate a memory obj");
    info!("Got frame_id {:#?}", frame_id);

    let tid = lineup::tls2::Environment::tid();
    let mut base: u64 = (0x1200_0000_0000 * tid.0 as u64) + 0xdeef_f000;
    let size: u64 = BASE_PAGE_SIZE as u64;

    let mut iops = 0;
    let mut iterations = 10;
    while iterations > 0 {
        let start = rawtime::Instant::now();
        while start.elapsed().as_millis() < 250 {
            unsafe { VSpace::map(base, size).expect("Map syscall failed") };
            iops += 1;
            base += BASE_PAGE_SIZE as u64;
        }
        info!("IOPS {}", iops);
        iops = 0;
        iterations -= 1;
    }
}

pub fn bench() {
    let threads = vibrio::syscalls::System::threads().expect("Can't get system topology");
    let s = &vibrio::upcalls::PROCESS_SCHEDULER;

    for thread in threads {
        if thread.id == 0 {
            continue;
        }

        let r = vibrio::syscalls::Process::request_core(
            thread.id,
            VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
        );
        match r {
            Ok(_ctoken) => {
                s.spawn(
                    32 * 4096,
                    move |_| {
                        maponly_bencher();
                    },
                    ptr::null_mut(),
                    thread.id,
                );
            }
            Err(_e) => {
                error!("Failed to spawn to core {}", thread.id);
            }
        };
    }

    s.spawn(
        32 * 4096,
        move |_| unsafe {
            maponly_bencher();
        },
        ptr::null_mut(),
        0,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    loop {
        s.run(&scb);
    }
}
