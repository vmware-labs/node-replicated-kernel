// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! AArch64 specific kernel code.

use core::arch::asm;
use core::arch::global_asm;
use core::mem::transmute;

use cortex_a::{asm::barrier, registers::*};
use tock_registers::interfaces::{Readable, Writeable};

use crate::cmdline::CommandLineArguments;

pub use bootloader_shared::*;
use klogger::sprint;

pub mod debug;
mod exceptions;
pub mod kcb;
pub mod memory;
pub mod process;
pub mod signals;
mod syscall;
pub mod timer;
pub mod vspace;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;

// // Include the `jump_to_kernel` assembly function. This does some things we can't express in
// // rust like switching the stack.
// global_asm!(include_str!("exceptions.S"));

extern "C" {
    static __exn_vectors_start: u32;
    static __exn_vectors_end: u32;
}

/// Goes to sleep / halts the core.
///
/// Interrupts are enabled before going to sleep.
pub(crate) fn halt() -> ! {
    unsafe {
        loop {
            asm!("wfi")
        }
    }
}

/// For cores that advances the replica eagerly. This avoids additional IPI costs.
pub(crate) fn advance_fs_replica() {
    panic!("not yet implemented");
}

use core::ptr::{read_volatile, write_volatile};

/// Entry function that is called from UEFI At this point we are in x86-64
/// (long) mode, We have a simple GDT, our address space, and stack set-up. The
/// argc argument is abused as a pointer ot the KernelArgs struct passed by
/// UEFI.
#[cfg(target_os = "none")]
#[start]
#[no_mangle]
fn _start(argc: isize, _argv: *const *const u8) -> isize {
    // probably should make the address a cmdline argument at some point...
    klogger::init(
        crate::CMDLINE.get().map(|c| c.log_filter).unwrap_or("info"),
        0xffff_0000_0900_0000,
    )
    .expect("Can't set-up logging");

    let el = CurrentEL.read(CurrentEL::EL);
    log::info!("Starting kernel on aarch64 in EL{:?}", el);
    log::info!("Kernel starting at {:p}", &_start as *const _);

    // set up exception vectors with the assembly code
    unsafe {
        log::info!("Setting up exception vectors: {:p}", &__exn_vectors_start);
        let exn_vector_size =
            (&__exn_vectors_end as *const _ as u64) - (&__exn_vectors_start as *const _ as u64);
        if exn_vector_size != 2048 {
            panic!(
                "Exception vector size is not 2048 bytes (was: {})",
                exn_vector_size
            );
        }
        VBAR_EL1.set(&__exn_vectors_start as *const _ as u64);
        barrier::isb(barrier::SY);
    }

    // Make sure these constants are initialized early, for proper time
    // accounting (otherwise because they are lazy_static we may not end up
    // using them until way later).
    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // We construct a &'static for KernelArgs
    let kernel_args: &'static KernelArgs =
        // Safety:
        // - argc is of correct size and alignment: Yes, was allocated by
        //   bootloader
        // - argc is properly initialized: Yes, contract with bootloader
        // - argc is valid for &'static lifetime: Yes, bootloader reserved the
        //   memory for us
        unsafe { transmute::<u64, &'static KernelArgs>(argc as u64) };
    // Parse the command line arguments:

    log::info!(
        "Parsing command line arguments: {:p}...",
        kernel_args.command_line
    );
    let cmdline = CommandLineArguments::from_str(kernel_args.command_line);
    // Initialize cmdline arguments as global
    crate::CMDLINE.call_once(move || cmdline);
    // Initialize kernel arguments as global
    crate::KERNEL_ARGS.call_once(move || kernel_args);

    log::info!("Initializing VSpace");
    // Needs to be done before we switch address space
    // lazy_static::initialize(&vspace::INITIAL_VSPACE);

    log::info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    halt();
}
