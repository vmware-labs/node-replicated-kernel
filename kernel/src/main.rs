//! The bespin kernel.
//!
//! Here we define the core modules and the main function that the kernel runs after
//! the arch-specific initialization is done (see `arch/x86_64/mod.rs` for an example).

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

// TODO(cosmetics): Couldn't get rid of these three `extern crate` even though we're edition 2018:
extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate klogger;

/// The x86-64 platform specific code.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

/// The unix platform specific code.
#[cfg(all(target_arch = "x86_64", target_family = "unix"))]
#[path = "arch/unix/mod.rs"]
pub mod arch;

/// To write unit-tests for our bare-metal code, we include the x86_64
/// arch-specific code on the `unix` platform.
#[cfg(all(test, target_arch = "x86_64", target_family = "unix"))]
#[path = "arch/x86_64/mod.rs"]
pub mod x86_64_arch;

mod error;
mod graphviz;
mod kcb;
mod memory;
mod nr;
mod prelude;
mod process;
mod stack;

pub mod panic;

/// A kernel exit status.
///
/// This is used to communicate the exit status
/// (if somehow possible) to the outside world.
///
/// If we run in qemu a special ioport can be used
/// to exit the VM and communicate the status to the host.
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

/// Kernel entry-point (after initialization has completed).
///
/// # Notes
/// This function is executed from each core (which is
/// different from a traditional main routine).
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

// Including a series of other, custom `xmain` routines that get
// selected when compiling for a specific integration test
include!("integration_main.rs");
