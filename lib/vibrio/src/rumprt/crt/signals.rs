// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! POSIX signals implementation
//!
//! Just very basic stubs for now.

use crate::rumprt::{c_int, c_void};

/// C wrapper for `sigset_t` type.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct SigSet {
    pub bits: [u32; 4usize],
}

/// Capable to store the different signal handler routines.
///
/// C type wrapper for signal handler union in `struct sigaction`.
#[repr(C)]
#[derive(Copy, Clone)]
pub union SigActionHandler {
    pub handler: Option<unsafe extern "C" fn(arg1: c_int)>,
    pub sigaction: Option<unsafe extern "C" fn(arg1: c_int, arg2: *mut c_void, arg3: *mut c_void)>,
    _bindgen_union_align: u64,
}

/// Signal vector "template" used in sigaction call.
///
/// C wrapper for `struct sigaction`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SigAction {
    pub u: SigActionHandler,
    pub mask: SigSet,
    pub flags: c_int,
}

const SIG_IGN: u64 = 1;

unsafe fn sigaction(_sig: c_int, _act: *const SigAction, oact: *mut SigAction) -> c_int {
    if !oact.is_null() {
        let sa: SigAction = SigAction {
            u: SigActionHandler {
                _bindgen_union_align: SIG_IGN,
            },
            mask: Default::default(),
            flags: 0,
        };
        *oact = sa;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn _sys___sigprocmask14(
    _how: c_int,
    _set: *const SigSet,
    oset: *mut SigSet,
) -> c_int {
    if !oset.is_null() {
        *oset = Default::default();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn __sigaction14(
    sig: c_int,
    act: *const SigAction,
    oact: *mut SigAction,
) -> c_int {
    sigaction(sig, act, oact)
}

#[no_mangle]
pub unsafe extern "C" fn ____sigtimedwait50() {
    unreachable!("____sigtimedwait50");
}

#[no_mangle]
pub unsafe extern "C" fn _sys___sigsuspend14() {
    unreachable!("_sys___sigsuspend14");
}
