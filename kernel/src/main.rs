#![no_std]
#![feature(
    intrinsics,
    core_intrinsics,
    asm,
    lang_items,
    const_fn,
    raw,
    box_syntax,
    start,
    panic_info_message,
    allocator_api,
    global_asm,
    linkage,
    c_variadic,
    alloc_layout_extra,
    ptr_internals,
    compiler_builtins_lib,
    ptr_offset_from,
    box_into_raw_non_null,
    box_into_pin,
    untagged_unions,
    const_raw_ptr_to_usize_cast,
    maybe_uninit_extra,
    maybe_uninit_ref
)]
#![allow(safe_packed_borrows)]

#[cfg(not(target_os = "none"))]
extern crate libc;

#[macro_use]
pub mod mutex;

extern crate alloc;
extern crate custom_error;

#[macro_use]
extern crate log;

#[cfg(target_arch = "x86_64")]
extern crate x86;

#[cfg(target_arch = "x86_64")]
extern crate apic;

#[cfg(target_arch = "x86_64")]
extern crate slabmalloc;

#[cfg(target_arch = "x86_64")]
#[macro_use]
extern crate klogger;

#[cfg(target_arch = "x86_64")]
extern crate elfloader;

#[cfg(target_arch = "x86_64")]
extern crate topology;

extern crate backtracer;
extern crate rawtime;

#[macro_use]
extern crate lazy_static;

pub use klogger::*;

#[cfg(target_os = "none")]
pub mod panic;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

#[cfg(all(target_arch = "x86_64", target_family = "unix"))]
#[path = "arch/unix/mod.rs"]
pub mod arch;

mod kcb;
mod memory;
#[macro_use]
mod prelude;
mod error;
mod graphviz;
mod nr;
mod stack;

#[cfg(target_os = "none")]
extern crate acpica_sys;

use core::alloc::{GlobalAlloc, Layout};
use spin::Mutex;

mod std {
    pub use core::cmp;
    pub use core::fmt;
    pub use core::iter;
    pub use core::marker;
    pub use core::ops;
    pub use core::option;
}

/// A kernel exit code (used to communicate the exit status for
/// tests to qemu).
///
/// # Notes
/// If this type is modified, update the `run.sh` script as well.
#[repr(u8)]
pub enum ExitReason {
    Ok = 0,
    ReturnFromMain = 1,
    KernelPanic = 2,
    OutOfMemory = 3,
    UnhandledInterrupt = 4,
    GeneralProtectionFault = 5,
    PageFault = 6,
    UserSpaceError = 7,
    ExceptionDuringInitialization = 8,
    UnrecoverableError = 9,
}

/// Kernel entry-point
#[no_mangle]
#[cfg(not(feature = "integration-test"))]
pub fn xmain() {
    debug!("Reached architecture independent area");
    error!("error");
    warn!("warning");
    info!("info");
    debug!("debug");
    trace!("trace");

    debug!("allocating a region of mem");
    unsafe {
        {
            let mem_mgmt = kcb::get_kcb().mem_manager();
            //info!("{:?}", mem_mgmt);
        }
        let new_region: *mut u8 =
            alloc::alloc::alloc(Layout::from_size_align_unchecked(8192, 4096));
        let p: *mut u8 = new_region.offset(4096);
        assert!(!p.is_null());

        {
            let mem_mgmt = kcb::get_kcb().mem_manager();
            //info!("{:?}", mem_mgmt);
        }
    }

    arch::debug::shutdown(ExitReason::Ok);
}

include!("integration_main.rs");
