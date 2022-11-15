// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::halt;

/// Hander for unsupported exceptions
///
/// # Argument

#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_syscall(
    function: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    context: u64,
) -> ! {
    log::error!(
        "Handle syscalls!: {:x} {:x} {:x} {:x}",
        function,
        arg1,
        arg2,
        arg3
    );
    halt()
}
