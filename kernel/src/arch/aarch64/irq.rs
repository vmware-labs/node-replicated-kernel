// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Interrupt Handling.

/// Rust entry point for exception handling (see isr.S).
/// TODO: does this need to be extern?
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_interrupt() -> ! {
    log::warn!("interrupt  has happened!");
    loop {}
}
