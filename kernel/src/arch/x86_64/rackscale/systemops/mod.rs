// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use kpi::system::{GlobalThreadId, NodeId, PackageId};

use super::utils::get_num_workers;
use crate::cmdline::MachineId;

pub mod get_hardware_threads;

// Helper functions for CpuThread GlobalThreadId
pub(crate) fn local_to_gtid(gtid: GlobalThreadId, machine_id: MachineId) -> GlobalThreadId {
    get_num_workers() as GlobalThreadId * gtid + machine_id as GlobalThreadId
}

pub(crate) fn gtid_to_local(gtid: GlobalThreadId, machine_id: MachineId) -> GlobalThreadId {
    (gtid - machine_id as GlobalThreadId) / get_num_workers() as GlobalThreadId
}

pub(crate) fn is_gtid_local(gtid: GlobalThreadId, machine_id: MachineId) -> bool {
    gtid % get_num_workers() as GlobalThreadId == machine_id as GlobalThreadId
}

// Helper functions for CpuThread NodeId
pub(crate) fn local_to_node_id(node_id: NodeId, machine_id: MachineId) -> NodeId {
    get_num_workers() as NodeId * node_id + machine_id as NodeId
}

pub(crate) fn node_id_to_local(node_id: NodeId, machine_id: MachineId) -> NodeId {
    (node_id - machine_id as NodeId) / get_num_workers() as NodeId
}

pub(crate) fn is_node_id_local(node_id: NodeId, machine_id: MachineId) -> bool {
    node_id % get_num_workers() as NodeId == machine_id as NodeId
}

// Helper functions for CpuThread PackageId
pub(crate) fn local_to_package_id(package_id: PackageId, machine_id: MachineId) -> PackageId {
    get_num_workers() as PackageId * package_id + machine_id as PackageId
}

pub(crate) fn package_id_to_local(package_id: PackageId, machine_id: MachineId) -> PackageId {
    (package_id - machine_id as PackageId) / get_num_workers() as PackageId
}

pub(crate) fn is_package_id_local(package_id: PackageId, machine_id: MachineId) -> bool {
    package_id % get_num_workers() as PackageId == machine_id as PackageId
}
