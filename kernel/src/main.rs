// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The nrk kernel.
//!
//! Here we define the core modules and the main function that the kernel runs after
//! the arch-specific initialization is done (see `arch/x86_64/mod.rs` for an example).

#![cfg_attr(target_os = "none", no_std)]
#![deny(warnings)]
#![cfg_attr(target_family = "unix", allow(unused))]
#![feature(
    is_sorted,
    intrinsics,
    core_intrinsics,
    lang_items,
    asm_const,
    start,
    box_syntax,
    panic_info_message,
    allocator_api,
    linkage,
    c_variadic,
    drain_filter,
    let_chains,
    new_uninit,
    get_mut_unchecked,
    const_refs_to_cell,
    nonnull_slice_from_raw_parts,
    cell_update,
    thread_local,
    maybe_uninit_write_slice,
    alloc_error_handler
)]

extern crate alloc;

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

mod environment;
mod error;
mod fs;
mod graphviz;
mod memory;
mod nr;
mod nrproc;
#[macro_use]
mod prelude;
mod cmdline;
mod fallible_string;
mod mpmc;
mod pci;
mod process;
mod scheduler;
mod stack;
mod syscalls;
mod transport;

pub mod panic;

use spin::Once;

/// Arguments passed form the bootloader to the kernel.
pub(crate) static KERNEL_ARGS: Once<&'static crate::arch::KernelArgs> = Once::new();

/// Parsed arguments passed from the user to the kernel (via command line args).
pub(crate) static CMDLINE: Once<cmdline::CommandLineArguments> = Once::new();

#[cfg(feature = "integration-test")]
mod integration_tests;

/// A kernel exit status.
///
/// This is used to communicate the exit status
/// (if somehow possible) to the outside world.
///
/// If we run in qemu a special ioport can be used
/// to exit the VM and communicate the status to the host.
///
/// # Notes
/// If this type is modified, update the `run.py` script and `testutils/*.rs` as well.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub(crate) enum ExitReason {
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
pub(crate) fn main() {
    #[cfg(feature = "rackscale")]
    if CMDLINE
        .get()
        .map_or(false, |c| c.mode == cmdline::Mode::Controller)
    {
        arch::rackscale::controller::run();
    }

    #[cfg(not(feature = "integration-test"))]
    {
        let ret = arch::process::spawn("init");
        if let Err(e) = ret {
            log::warn!("{}", e);
        }
        crate::scheduler::schedule()
    }
    #[cfg(feature = "integration-test")]
    {
        log::debug!("About to run '{:?}'", CMDLINE.get().map(|c| c.test));
        if let Some(test) = CMDLINE.get().and_then(|c| c.test) {
            integration_tests::run_test(test)
        } else {
            log::error!("No test selected, exiting...");
        }
    }
}
