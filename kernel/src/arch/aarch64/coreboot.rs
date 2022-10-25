// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;

use cnr::Log as MlnrLog;
use cnr::Replica as MlnrReplica;
use node_replication::{Log, Replica};

use crate::fs::cnrfs::MlnrKernelNode;
use crate::fs::cnrfs::Modify;
use crate::nr::KernelNode;
use crate::nr::Op;

/// Initialize the rest of the cores in the system.
///
/// # Arguments
/// - `kernel_binary` - A slice of the kernel binary.
/// - `kernel_args` - Intial arguments as passed by UEFI to the kernel.
/// - `global_memory` - Memory allocator collection.
/// - `log` - A reference to the operation log.
/// - `bsp_replica` - Replica that the BSP core created and is registered to.
///
/// # Notes
/// Dependencies for calling this function are:
///  - Initialized ACPI
///  - Initialized topology
///  - Local APIC driver
pub(super) fn boot_app_cores(
    log: Arc<Log<'static, Op>>,
    bsp_replica: Arc<Replica<'static, KernelNode>>,
    fs_logs: Vec<Arc<MlnrLog<'static, Modify>>>,
    fs_replica: Arc<MlnrReplica<'static, MlnrKernelNode>>,
) {
}
