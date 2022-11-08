// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::alloc::Layout;

use super::{SchedulerControlBlock, ThreadControlBlock};
use crate::threads::ThreadId;

pub(crate) unsafe fn get_tcb<'a>() -> *mut ThreadControlBlock<'a> {
    panic!("nyi: get_tcb")
}

pub(crate) unsafe fn set_tcb(t: *mut ThreadControlBlock) {
    panic!("nyi: set_tcb")
}

pub(crate) unsafe fn get_scb() -> *const SchedulerControlBlock {
    panic!("nyi: get_scb")
}

pub(crate) unsafe fn set_scb(scb: *const SchedulerControlBlock) {
    panic!("nyi: set_scb")
}

pub fn thread<'a>() -> &'a mut ThreadControlBlock<'static> {
    panic!("nyi: thread")
}

pub fn tid() -> ThreadId {
    panic!("nyi: tid")
}

/// Determines the necessary space for per-thread TLS memory region.
///
/// Total required bytes is the sum of the `tdata`, `tbss`,
/// and a statically defined extra section.
/// (i.e., the sum of all return values)
pub fn get_tls_info() -> (&'static [u8], Layout) {
    panic!("nyi: get_tls_info")
}
