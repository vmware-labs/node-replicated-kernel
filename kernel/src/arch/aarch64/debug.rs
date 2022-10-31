// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::arch::asm;
use klogger::sprintln;

use crate::ExitReason;

pub(crate) fn init() {}

pub unsafe fn getc() -> char {
    log::error!("getc() not implemented");
    unimplemented!()
}

/// Write a string to the output channel
pub unsafe fn puts(s: &str) {
    sprintln!("{}", s);
}

/// Shutdown the processor.
///
/// Currently we only support the debug exit method from qemu, which conveniently
/// allows us to supply an exit code for testing purposes.
pub(crate) fn shutdown(val: ExitReason) -> ! {
    // For CI run.py bare-metal execution, parses exit code
    // (Do not change this line without adjusting run.py)
    sprintln!("[shutdown-request] {}", val as u8);

    loop {
        unsafe { asm!("wfi") };
    }
}
