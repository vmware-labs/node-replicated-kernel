// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KCB is the local kernel control that stores all core local state.

use alloc::sync::Arc;
use core::any::Any;
use core::cell::{RefCell, RefMut};

use cnr::{Replica as MlnrReplica, ReplicaToken as MlnrReplicaToken};
use node_replication::{Replica, ReplicaToken};

use crate::mlnr::MlnrKernelNode;
use crate::nr::KernelNode;
use crate::process::ProcessError;
use crate::{
    kcb::{ArchSpecificKcb, BootloaderArguments, Kcb},
    memory::tcache_sp::TCacheSp,
};

use super::process::{UnixProcess, UnixThread};
use super::vspace::VSpace;
use super::KernelArgs;

static KERNEL_ARGS: KernelArgs = KernelArgs::new();

#[thread_local]
static mut KCB: Kcb<ArchKcb> = {
    Kcb::new(
        &[],
        BootloaderArguments::new("info", "init", "init", "init"),
        TCacheSp::new(0, 0),
        ArchKcb::new(&KERNEL_ARGS),
        0,
    )
};

pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb<ArchKcb>> {
    unsafe { Some(&mut KCB) }
}

pub fn get_kcb<'a>() -> &'a mut Kcb<ArchKcb> {
    unsafe { &mut KCB }
}

/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb<A: ArchSpecificKcb + Any>(mut _kcb: &'static mut Kcb<A>) {
    //unreachable!("init_kcb.");
}

#[repr(C)]
pub struct ArchKcb {
    init_vspace: Option<RefCell<VSpace>>,
    /// Arguments passed to the kernel by the bootloader.
    kernel_args: &'static KernelArgs,
    pub replica: Option<(Arc<Replica<'static, KernelNode<UnixProcess>>>, ReplicaToken)>,
    pub mlnr_replica: Option<(Arc<MlnrReplica<'static, MlnrKernelNode>>, MlnrReplicaToken)>,
    pub current_process: Option<Arc<UnixThread>>,
}

impl ArchKcb {
    pub const fn new(kernel_args: &'static KernelArgs) -> ArchKcb {
        ArchKcb {
            kernel_args,
            init_vspace: None,
            replica: None,
            mlnr_replica: None,
            current_process: None,
        }
    }

    pub fn init_vspace(&self) -> RefMut<VSpace> {
        let ivp = self.init_vspace.as_ref().unwrap();
        ivp.borrow_mut()
    }

    pub fn kernel_args(&self) -> &'static KernelArgs {
        self.kernel_args
    }

    pub fn id(&self) -> usize {
        0
    }

    pub fn max_threads(&self) -> usize {
        0
    }

    pub fn swap_current_process(
        &mut self,
        new_current_process: Arc<UnixThread>,
    ) -> Option<Arc<UnixThread>> {
        None
    }

    pub fn has_current_process(&self) -> bool {
        self.current_process.is_some()
    }

    pub fn current_process(&self) -> Result<Arc<UnixThread>, ProcessError> {
        let p = self
            .current_process
            .as_ref()
            .ok_or(ProcessError::ProcessNotSet)?;
        Ok(p.clone())
    }
}

impl ArchSpecificKcb for ArchKcb {
    type Process = UnixProcess;

    fn install(&mut self) {}

    fn hwthread_id(&self) -> u64 {
        0
    }
}
