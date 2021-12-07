// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The nrk kernel.
//!
//! Here we define the core modules and the main function that the kernel runs after
//! the arch-specific initialization is done (see `arch/x86_64/mod.rs` for an example).

#![cfg_attr(target_os = "none", no_std)]
#![deny(warnings)]
#![feature(
    is_sorted,
    intrinsics,
    core_intrinsics,
    llvm_asm,
    asm,
    lang_items,
    start,
    box_syntax,
    panic_info_message,
    allocator_api,
    global_asm,
    linkage,
    c_variadic,
    box_into_pin,
    maybe_uninit_ref,
    drain_filter,
    alloc_prelude,
    try_reserve,
    new_uninit,
    get_mut_unchecked,
    const_fn_trait_bound,
    const_ptr_offset_from,
    const_raw_ptr_deref,
    const_maybe_uninit_as_ptr,
    const_refs_to_cell,
    nonnull_slice_from_raw_parts,
    once_cell
)]
#![cfg_attr(not(target_os = "none"), feature(thread_local))]

extern crate alloc;

#[cfg(any(feature = "controller", feature = "exokernel"))]
#[macro_use]
extern crate abomonation;

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

mod cnrfs;
mod error;
mod fs;
mod graphviz;
mod kcb;
mod memory;
mod nr;
mod nrproc;
#[macro_use]
mod prelude;
mod fallible_string;
mod mpmc;
mod process;
mod scheduler;
mod stack;

pub mod panic;

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
/// If this type is modified, update the `run.py` script and `tests/integration-test.rs` as well.
#[derive(Copy, Clone, Debug)]
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
pub fn xmain() {
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
        log::debug!("About to run '{:?}'", kcb::get_kcb().cmdline.test);
        if let Some(test) = kcb::get_kcb().cmdline.test {
            integration_tests::run_test(test)
        } else {
            log::error!("No test selected, exiting...");
        }
    }
}
