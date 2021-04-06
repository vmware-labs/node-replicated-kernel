// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(lang_items, core_intrinsics)]
#![feature(start)]
#![no_std]
#![no_main]
use core::intrinsics;
use core::panic::PanicInfo;

extern crate vibrio;

// Entry point for this program.
#[no_mangle] // ensure that this symbol is called `main` in the output
pub extern "C" fn rump_main1(_argc: i32, _argv: *const *const u8) -> i32 {
    0
}
