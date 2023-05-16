// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Data structures to exchange system-wide information between kernel and user-space.
use abomonation::{unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

/// GlobalThreadId to match atopology::GlobalThreadId
pub type MachineThreadId = usize;

/// Machine identifier. This is used in rackscale deployments.
/// Defaults to 0 in single-machine deployments.
pub type MachineId = usize;

/// A system global ID for a CPU hardware thread.
/// High bits are for MachineId, low bits are for MachineThreadId.
pub type GlobalThreadId = usize;

#[inline(always)]
pub fn new_gtid(mtid: MachineThreadId, mid: MachineId) -> GlobalThreadId {
    (mid << (usize::BITS >> 1) as usize) | mtid
}

#[inline(always)]
pub fn mtid_from_gtid(gtid: GlobalThreadId) -> MachineThreadId {
    (gtid << (usize::BITS >> 1) as usize) >> (usize::BITS >> 1) as usize
}

#[inline(always)]
pub fn mid_from_gtid(gtid: GlobalThreadId) -> MachineId {
    gtid >> (usize::BITS >> 1) as usize
}

/// A hardware scheduling unit (has an APIC), (unique within a core).
pub type ThreadId = usize;

/// A core, with one or more threads (unique within a packet).
pub type CoreId = usize;

/// A socket with one or more cores (usually with a shared LLC).
pub type PackageId = usize;

/// Affinity region, a NUMA node (consists of a bunch of threads/core/packages and memory regions).
pub type NodeId = usize;

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Copy, Clone)]
pub struct CpuThread {
    /// ID the thread, global within a rackscale system.
    pub id: GlobalThreadId,
    /// ID of the NUMA node (machine global).
    pub node_id: NodeId,
    /// ID of the package (machine global).
    pub package_id: PackageId,
    /// ID of the core (relative to the package).
    pub core_id: CoreId,
    /// ID of the thread (relative to the core (usually either 0 or 1)).
    pub thread_id: ThreadId,
}
unsafe_abomonate!(CpuThread: id, node_id, package_id, core_id, thread_id);
