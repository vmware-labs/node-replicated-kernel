// Copyright © 2023 VMware, Inc. and University of Colorado Boulder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Code to support allocation by shared memory affinity.
//!
//! Defines affinitys for 1 shmem region per machine in rackscale
//! deployment.

use atopology::NodeId;
use kpi::system::MachineId;

use crate::arch::MAX_NUMA_NODES;

#[allow(unused)]
#[inline(always)]
pub(crate) fn is_shmem_affinity(affinity: NodeId) -> bool {
    affinity >= MAX_NUMA_NODES
}

/// Get the id of the shmem region
#[allow(unused)]
#[inline(always)]
pub(crate) fn mid_to_shmem_affinity(mid: MachineId) -> NodeId {
    // shmem regions are placed after local numa, so offset by MAX_NUMA_NODES
    MAX_NUMA_NODES + (mid as NodeId)
}

#[allow(unused)]
#[inline(always)]
pub(crate) fn shmem_affinity_to_mid(affinity: NodeId) -> MachineId {
    // shmem regions are placed after local numa, so offset by MAX_NUMA_NODES
    affinity - MAX_NUMA_NODES
}

#[allow(unused)]
#[inline(always)]
pub(crate) fn local_shmem_affinity() -> NodeId {
    mid_to_shmem_affinity(*crate::environment::MACHINE_ID)
}
