#![no_std]
#![feature(
    intrinsics,
    core_intrinsics,
    asm,
    lang_items,
    start,
    box_syntax,
    panic_info_message,
    allocator_api,
    global_asm,
    linkage,
    c_variadic,
    box_into_raw_non_null,
    box_into_pin,
    maybe_uninit_ref
)]
#![allow(safe_packed_borrows)] // TODO(warnings)

extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate klogger;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

#[cfg(all(target_arch = "x86_64", target_family = "unix"))]
#[path = "arch/unix/mod.rs"]
pub mod arch;

mod error;
mod graphviz;
mod kcb;
mod memory;
mod nr;
mod prelude;
mod stack;

#[cfg(target_os = "none")]
pub mod panic;

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
            alloc::alloc::alloc(core::alloc::Layout::from_size_align_unchecked(8192, 4096));
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
