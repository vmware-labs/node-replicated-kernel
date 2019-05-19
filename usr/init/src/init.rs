#![no_std]
#![no_main]

#[macro_use]
extern crate x86;

use core::panic::PanicInfo;


pub fn sys_print(buf: &str) {
    unsafe {
        let r = syscall!(0, 1, buf.as_ptr() as u64, buf.len());
        assert!(r == 0x0);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        sys_print("ttttt");

        //let r = syscall!(0, 1, 0);
        //assert!(r == 0x0);
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}