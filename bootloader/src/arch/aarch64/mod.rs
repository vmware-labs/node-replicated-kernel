// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::arch::global_asm;

pub mod cpu;
mod vspace;

pub use vspace::VSpaceAArch64 as VSpace;

// Include the `jump_to_kernel` assembly function. This does some things we can't express in
// rust like switching the stack.
global_asm!(include_str!("switch.S"), options(att_syntax));

/// The starting address of the kernel address space
///
/// All physical mappings are identity mapped with KERNEL_OFFSET as
/// displacement.
pub const KERNEL_OFFSET: usize = 1 << 48;
