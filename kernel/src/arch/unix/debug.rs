// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::ExitReason;
use klogger::sprintln;

/// Shutdown the process.
pub(crate) fn shutdown(val: ExitReason) -> ! {
    sprintln!("Shutdown {:?}", val);

    unsafe {
        libc::exit(val as i32);
    }
}
