// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Implements the interactions with the scheduler.
//!
//! Just stubs that don't to anything for now.

use crate::rumprt::{c_int, c_size_t, c_void, errno};

#[no_mangle]
pub unsafe extern "C" fn _sys_sched_yield() {
    unreachable!("_sys_sched_yield");
}

#[no_mangle]
pub unsafe extern "C" fn _sched_getaffinity() {
    unreachable!("_sched_getaffinity");
}

#[no_mangle]
pub unsafe extern "C" fn _sched_getparam() {
    unreachable!("_sched_getparam");
}

#[no_mangle]
pub unsafe extern "C" fn _sched_protect() -> c_int {
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn _sched_setaffinity() {
    unreachable!("_sched_setaffinity");
}

#[no_mangle]
pub unsafe extern "C" fn _sched_setparam() {
    unreachable!("_sched_setparam");
}

#[no_mangle]
pub unsafe extern "C" fn sched_yield() {
    log::error!("called sched_yield");
}

/// Restartable atomic sequences are code sequences which are guaranteed to
/// execute without preemption.  This property is assured by the kernel by
/// re-executing a preempted sequence from the start.
#[no_mangle]
pub unsafe extern "C" fn rasctl(_addr: *mut c_void, _len: c_size_t, _op: c_int) -> c_int {
    errno::ENOSYS
}
