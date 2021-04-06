// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A mechanism for upcalls that the scheduler uses to notify
//! an application about events: a thread is blocking etc.
//!
//! In the current form, simply modelled to support rump upcalls.
//! Should be generalized in the future.

use crate::mutex;
use core::fmt;

/// Notification up-calls from the scheduler to the application
/// (here to support the rump runtime).
#[derive(Clone, Copy)]
pub struct Upcalls {
    pub curlwp: fn() -> u64,
    pub schedule: fn(&i32, Option<&mutex::Mutex>),
    pub deschedule: fn(&mut i32, Option<&mutex::Mutex>),
    pub context_switch: fn(*mut u8, *mut u8),
}

impl Default for Upcalls {
    fn default() -> Self {
        Upcalls {
            curlwp: noop_curlwp,
            schedule: noop_schedule,
            deschedule: noop_unschedule,
            context_switch: noop_context_switch,
        }
    }
}

impl fmt::Debug for Upcalls {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Upcalls {{}}")
    }
}

/// Dummy implementation of noop_context_switch().
fn noop_context_switch(_a1: *mut u8, _a2: *mut u8) {}

/// Dummy implementation of noop_curlwp().
fn noop_curlwp() -> u64 {
    0
}

/// Dummy implementation of unschedule().
fn noop_unschedule(_nlocks: &mut i32, _mtx: Option<&mutex::Mutex>) {}

/// Dummy implementation of schedule().
fn noop_schedule(_nlocks: &i32, _mtx: Option<&mutex::Mutex>) {}
