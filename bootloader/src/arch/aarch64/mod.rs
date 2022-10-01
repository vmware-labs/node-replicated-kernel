// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::arch::global_asm;

pub mod cpu;
mod vspace;

use armv8::aarch64::registers::Currentel;

pub use armv8::aarch64::vm::granule4k::{PAddr, VAddr};
pub use armv8::aarch64::vm::granule4k::{BASE_PAGE_SHIFT, HUGE_PAGE_SHIFT, LARGE_PAGE_SHIFT};
pub use armv8::aarch64::vm::granule4k::{BASE_PAGE_SIZE, HUGE_PAGE_SIZE, LARGE_PAGE_SIZE};
pub use vspace::map_physical_memory;
pub use vspace::VSpaceAArch64 as VSpace;

// Include the `jump_to_kernel` assembly function. This does some things we can't express in
// rust like switching the stack.
global_asm!(include_str!("switch.S"));

global_asm!(include_str!("__chkstk.S"));

/// The starting address of the kernel address space
///
/// All physical mappings are identity mapped with KERNEL_OFFSET as
/// displacement.
pub const KERNEL_OFFSET: usize = 1 << 48;

/// prints some architecture specific strings
pub fn print_arch() {
    info!("Running on Arm in EL{}", Currentel::el_read());
}
