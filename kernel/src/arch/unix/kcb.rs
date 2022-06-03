// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KCB is the local kernel control that stores all core local state.

use alloc::sync::Arc;
use core::any::Any;

use arrayvec::ArrayVec;
use node_replication::{Replica, ReplicaToken};

use crate::error::KError;
use crate::kcb::PerCoreMemory;
use crate::memory::mcache::FrameCacheEarly;
use crate::nr::KernelNode;
use crate::nrproc::NrProcess;
use crate::process::MAX_PROCESSES;

use super::process::{UnixProcess, UnixThread};
use super::MAX_NUMA_NODES;

#[thread_local]
static mut KCB: PerCoreMemory<ArchKcb> =
    PerCoreMemory::new(FrameCacheEarly::new(0), ArchKcb::new(), 0);

pub(crate) fn try_get_kcb<'a>() -> Option<&'a mut PerCoreMemory<ArchKcb>> {
    unsafe { Some(&mut KCB) }
}

pub(crate) fn get_kcb<'a>() -> &'a mut PerCoreMemory<ArchKcb> {
    unsafe { &mut KCB }
}

pub(crate) fn try_per_core_mem() -> Option<&'static PerCoreMemory> {
    unreachable!("per_core_mem.");
}

/// Stands for per-core memory
pub(crate) fn per_core_mem() -> &'static PerCoreMemory {
    unreachable!("per_core_mem.");
}

/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb(mut _kcb: &'static mut PerCoreMemory) {
    //unreachable!("init_kcb.");
}

#[repr(C)]
pub(crate) struct ArchKcb {
    /// Arguments passed to the kernel by the bootloader.
    pub replica: Option<(Arc<Replica<'static, KernelNode>>, ReplicaToken)>,
    pub current_executor: Option<Box<UnixThread>>,
}

impl ArchKcb {
    pub(crate) const fn new() -> ArchKcb {
        ArchKcb {
            replica: None,
            current_executor: None,
        }
    }

    pub(crate) fn id(&self) -> usize {
        0
    }

    pub(crate) fn has_executor(&self) -> bool {
        self.current_executor.is_some()
    }

    pub(crate) fn current_executor(&self) -> Result<&UnixThread, KError> {
        let p = self
            .current_executor
            .as_ref()
            .ok_or(KError::ProcessNotSet)?;
        Ok(p)
    }
}

impl ArchSpecificKcb for ArchKcb {
    type Process = UnixProcess;

    fn install(&mut self) {}

    #[allow(clippy::type_complexity)] // fix this once `associated_type_defaults` works
    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    > {
        &*super::process::PROCESS_TABLE
    }
}
