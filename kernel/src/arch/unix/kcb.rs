// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KCB is the local kernel control that stores all core local state.

use alloc::sync::Arc;
use core::any::Any;

use arrayvec::ArrayVec;
use node_replication::{Replica, ReplicaToken};

use crate::error::KError;
use crate::memory::mcache::FrameCacheEarly;
use crate::memory::per_core::PerCoreMemory;
use crate::nr::KernelNode;
use crate::nrproc::NrProcess;
use crate::process::MAX_PROCESSES;

use super::process::{UnixProcess, UnixThread};
use super::MAX_NUMA_NODES;

#[thread_local]
pub(crate) static mut PER_CORE_MEMORY: PerCoreMemory =
    PerCoreMemory::new(FrameCacheEarly::new(0), 0);

#[thread_local]
static mut KCB: ArchKcb = ArchKcb;

pub(crate) fn try_get_kcb<'a>() -> Option<&'a mut ArchKcb> {
    unsafe { Some(&mut KCB) }
}

pub(crate) fn get_kcb<'a>() -> &'a mut ArchKcb {
    unsafe { &mut KCB }
}

pub(crate) fn try_per_core_mem() -> Option<&'static PerCoreMemory> {
    unsafe { Some(&PER_CORE_MEMORY) }
}

/// Stands for per-core memory
pub(crate) fn per_core_mem() -> &'static PerCoreMemory {
    unsafe { &PER_CORE_MEMORY }
}

/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb(mut _kcb: &'static mut PerCoreMemory) {
    //unreachable!("init_kcb.");
}

#[repr(C)]
pub(crate) struct ArchKcb;
