// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub fn sp() -> u64 {
    armv8::aarch64::registers::SpEl0::val_read()
}

/// Resume a `state` that was saved by the kernel on a trap or interrupt.
pub unsafe fn resume(_control: &mut kpi::arch::VirtualCpu) -> ! {
    unimplemented!("add me");
}

/// Well, let's just hope the assembler continues to put this immediatly after
/// `resume()` in the binary...
#[no_mangle]
pub unsafe fn resume_end() {
    unreachable!("resume_end")
}
