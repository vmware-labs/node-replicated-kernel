use log::Level;
use spin::Mutex;

use crate::xmain;
use crate::ExitReason;

use crate::memory::buddy::BuddyFrameAllocator;
use crate::memory::{Frame, PhysicalAllocator};

pub mod irq;
pub mod kcb;
pub mod memory;
pub mod process;

pub mod debug {
    use crate::ExitReason;
    pub fn shutdown(val: ExitReason) -> ! {
        unsafe {
            libc::exit(val as i32);
        }
    }

}

#[start]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    // Note anything lower than Info is currently broken
    // because macros in mem management will do a recursive
    // allocation and this stuff is not reentrant...
    klogger::init(Level::Info).expect("Can't set-up logging");

    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    trace!("setting the kcb");
    // Allocate 32 MiB and add it to our heap
    let mut mb = BuddyFrameAllocator::new();
    let mut mm = memory::MemoryMapper::new();

    unsafe {
        let frame = mm
            .allocate_frame(32 * 1024 * 1024)
            .expect("We don't have vRAM available");
        mb.add_memory(frame);
    }

    // Construct the Kcb so we can access these things later on in the code

    let mut kcb = kcb::Kcb::new(mb);
    kcb::init_kcb(kcb);
    debug!("Memory allocation should work at this point...");

    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );


    xmain();

    ExitReason::ReturnFromMain as isize
}
