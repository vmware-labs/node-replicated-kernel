// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A silly implementation of get/set tcb/scb on unix
//!
//! Super meta since we use posix/thread_local to
//! implement it.
use core::alloc::Layout;
use core::cell::Cell;
use core::{mem, ptr};

use super::{SchedulerControlBlock, ThreadControlBlock};

#[thread_local]
pub static TCB: Cell<*mut ThreadControlBlock> = Cell::new(ptr::null_mut());

#[thread_local]
pub static SCB: Cell<*const SchedulerControlBlock> = Cell::new(ptr::null());

pub(crate) unsafe fn get_tcb<'a>() -> *mut ThreadControlBlock<'a> {
    mem::transmute::<*mut ThreadControlBlock<'static>, *mut ThreadControlBlock<'a>>(TCB.get())
}

pub(crate) unsafe fn set_tcb<'a>(tcb: *mut ThreadControlBlock<'a>) {
    TCB.set(mem::transmute::<
        *mut ThreadControlBlock<'a>,
        *mut ThreadControlBlock<'static>,
    >(tcb));
}

pub(crate) unsafe fn get_scb() -> *const SchedulerControlBlock {
    SCB.get()
}

pub(crate) unsafe fn set_scb(scb: *const SchedulerControlBlock) {
    SCB.set(scb);
}

/// A poor way to estimate the TLS size on unix.
#[cfg(target_family = "unix")]
pub fn get_tls_info() -> (&'static [u8], Layout) {
    // We only use this for tests, so we just estimate our TLS size...
    // Ideally we parse the ELF of our process to determine the static TLS size
    (&[], Layout::new::<ThreadControlBlock>())
}
