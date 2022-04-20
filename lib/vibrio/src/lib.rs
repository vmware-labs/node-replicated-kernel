// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! vibrio is the user-space library that interacts with the kernel.
//!
//! It also incorporates and exports the [kpi] crate which defines the interface between
//! the kernel and user-space (clients should only have to rely on this crate).
#![no_std]
#![feature(
    asm_const,
    alloc_error_handler,
    panic_info_message,
    c_variadic,
    ptr_internals,
    lang_items,
    thread_local
)]
extern crate alloc;
extern crate kpi;
#[cfg(not(target_os = "nrk"))]
extern crate std;

pub use kpi::*;

extern crate arrayvec;
extern crate lazy_static;

pub mod mem;
#[cfg(target_os = "nrk")]
pub mod upcalls;
pub mod vconsole;
pub mod writer;

#[cfg(feature = "rumprt")]
pub mod rumprt;

#[cfg(target_os = "nrk")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    sys_println!("System panic encountered");
    if let Some(message) = info.message() {
        sys_print!(": '{}'", message);
    }
    if let Some(location) = info.location() {
        sys_println!(" in {}:{}", location.file(), location.line());
    } else {
        sys_println!("");
    }

    unsafe {
        let rsp = x86::bits64::registers::rsp();
        for i in 0..32 {
            let ptr = (rsp as *const u64).offset(i);
            sys_println!("stack[{}] = {:#x}", i, *ptr);
        }
    }

    crate::syscalls::Process::exit(99)
}

#[cfg(target_os = "nrk")]
#[no_mangle]
pub unsafe extern "C" fn _Unwind_Resume() {
    unreachable!("_Unwind_Resume");
}

#[cfg(target_os = "nrk")]
#[lang = "eh_personality"]
pub extern "C" fn eh_personality() {}

#[cfg(target_os = "nrk")]
#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    panic!("oom {:?}", layout)
}
