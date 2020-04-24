//! vibrio is the user-space library that interacts with the kernel.
//!
//! It also incorporates and exports the [kpi] crate which defines the interface between
//! the kernel and user-space (clients should only have to rely on this crate).
#![no_std]
#![feature(
    alloc_error_handler,
    const_fn,
    panic_info_message,
    c_variadic,
    ptr_internals,
    ptr_offset_from,
    llvm_asm,
    lang_items,
    thread_local
)]
extern crate alloc;
extern crate kpi;

pub use kpi::io;
pub use kpi::syscalls;

#[cfg(feature = "rumprt")]
extern crate lazy_static;

pub mod mem;
pub mod writer;

pub mod upcalls;

#[cfg(feature = "rumprt")]
pub mod rumprt;

#[cfg(feature = "lklrt")]
pub mod lklrt;

#[cfg(target_os = "bespin")]
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

    crate::syscalls::Process::exit(99)
}

#[cfg(target_os = "bespin")]
#[no_mangle]
pub unsafe extern "C" fn _Unwind_Resume() {
    unreachable!("_Unwind_Resume");
}

#[cfg(target_os = "bespin")]
#[lang = "eh_personality"]
pub extern "C" fn eh_personality() {}

#[cfg(target_os = "bespin")]
#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    panic!("oom {:?}", layout)
}
