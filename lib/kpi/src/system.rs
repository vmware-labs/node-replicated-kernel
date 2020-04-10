//! Data structures to exchange system-wide information between kernel and user-space.

use serde::{Deserialize, Serialize};

/// A system global ID for a CPU hardware thread.
pub type GlobalThreadId = usize;

/// A hardware scheduling unit (has an APIC), (unique within a core).
pub type ThreadId = usize;

/// A core, with one or more threads (unique within a packet).
pub type CoreId = usize;

/// A socket with one or more cores (usually with a shared LLC).
pub type PackageId = usize;

/// Affinity region, a NUMA node (consists of a bunch of threads/core/packages and memory regions).
pub type NodeId = usize;

#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct CpuThread {
    /// ID the thread, global within a system.
    pub id: GlobalThreadId,
    /// ID of the NUMA node (system global).
    pub node_id: NodeId,
    /// ID of the package (system global).
    pub package_id: PackageId,
    /// ID of the core (relative to the package).
    pub core_id: CoreId,
    /// ID of the thread (relative to the core (usually either 0 or 1)).
    pub thread_id: ThreadId,
}
