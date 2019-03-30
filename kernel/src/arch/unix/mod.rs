use log::Level;
use spin::Mutex;

use crate::main;
use crate::ExitReason;

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

pub static KERNEL_BINARY: Mutex<Option<&'static [u8]>> = Mutex::new(None);

#[start]
#[no_mangle]
fn arch_init(_argc: isize, _argv: *const *const u8) -> isize {
    klogger::init(Level::Trace).expect("Can't set-up logging");
    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    main();

    ExitReason::ReturnFromMain as isize
}
