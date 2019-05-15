#![no_std]
#![no_main]

#[macro_use]
extern crate x86;

use core::panic::PanicInfo;


#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        syscall!(1, 1);
    }

    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}