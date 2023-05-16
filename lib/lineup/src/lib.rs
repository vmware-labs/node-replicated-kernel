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

/// A utility function that converts a core_id (which may not be sequential)
/// to a form more easily used for indexing
#[inline(always)]
pub fn core_id_to_index(core_id: CoreId) -> usize {
    let machine_id = kpi::system::mid_from_gtid(core_id);
    if machine_id == 0 {
        // This is controller (should never happen) or non-rackscale
        core_id
    } else {
        // The controller (which will never need this) is always machine_id 0, so
        // decrement here for rackscale clients.
        kpi::process::MAX_CORES_PER_MACHINE * (machine_id - 1)
            + kpi::system::mtid_from_gtid(core_id)
    }
}

/// Type to represent an IRQ vector.
type IrqVector = u64;
