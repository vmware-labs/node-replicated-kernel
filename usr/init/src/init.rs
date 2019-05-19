#![no_std]
#![no_main]

use core::panic::PanicInfo;
use kpi;


#[no_mangle]
pub extern "C" fn _start() -> ! {
    kpi::print("test");
    kpi::exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}