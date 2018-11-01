use log::Level;
use spin::Mutex;

use main;
use ExitReason;

pub mod memory;

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
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    klogger::init(Level::Trace).expect("Can't set-up logging");
    main();

    ExitReason::ReturnFromMain as isize
}
