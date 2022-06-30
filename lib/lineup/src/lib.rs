// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//!  A user-space thread scheduler with support for synchronization primitives.

#![feature(drain_filter)]
#![feature(linkage)]
#![feature(thread_local)]
#![feature(test)]
#![feature(asm_const)]
#![cfg_attr(test, feature(bench_black_box))]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod condvar;
pub mod mutex;
pub mod rwlock;
pub mod scheduler;
pub mod semaphore;
pub mod stack;
pub mod threads;
pub mod tls2;
pub mod upcalls;

/// Type to represent a core id for the scheduler.
type CoreId = usize;

/// Type to represent an IRQ vector.
type IrqVector = u64;
