// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::arch::global_asm;

mod vspace;

pub use vspace::VSpaceAArch64 as VSpace;

// extern "C" {
//     /// Switches from this UEFI bootloader to the kernel init function (passes the sysinfo argument),
//     /// kernel stack and kernel address space.
//     pub fn jump_to_kernel(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64);
// }



// // Include the `jump_to_kernel` assembly function. This does some things we can't express in
// // rust like switching the stack.
// global_asm!(include_str!("switch.S"), options(att_syntax));
