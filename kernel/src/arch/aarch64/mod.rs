// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! AArch64 specific kernel code.

use core::arch::asm;

pub use bootloader_shared::*;
use klogger::sprint;

pub mod debug;
pub mod kcb;
pub mod memory;
pub mod process;
pub mod signals;
pub mod timer;
pub mod vspace;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;

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
    const A: *mut u32 = (0xffff_0000_0900_0000) as *mut u32;

    unsafe {
        write_volatile(A, 'h' as u32);
        write_volatile(A, 'e' as u32);
        write_volatile(A, 'l' as u32);
        write_volatile(A, 'l' as u32);
        write_volatile(A, 'o' as u32);
        write_volatile(A, ' ' as u32);
        write_volatile(A, '\r' as u32);
        write_volatile(A, '\n' as u32);
    }

    sprint!("\r\n");
    sprint!("Hello from the kernel!\r");
    sprint!("\r\n");
    halt();
}
