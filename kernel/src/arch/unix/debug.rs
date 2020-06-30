use super::ExitReason;

/// Shutdown the process.
pub fn shutdown(val: ExitReason) -> ! {
    sprintln!("Shutdown {:?}", val);

    unsafe {
        libc::exit(val as i32);
    }
}
