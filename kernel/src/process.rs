//! Generic process traits
use crate::arch::Module;
use crate::memory::Frame;

/// Process ID.
pub type Pid = u64;

/// Executor ID.
pub type Eid = u64;

#[derive(Debug)]
pub enum ProcessError {
    UnableToLoad,
}

/// Abstract definition of a process.
pub trait Process {
    type E: Executor;

    fn new(module: &Module, pid: Pid) -> Result<Self, ProcessError>
    where
        Self: core::marker::Sized;

    fn try_reserve_dispatchers(
        how_many: usize,
        affinity: topology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError>;
    fn allocate_dispatchers(&mut self, frame: Frame) -> Result<(), ProcessError>;
}

/// ResumeHandle is the HW specific logic that switches the CPU
/// to the a new entry point by initializing the registers etc.
pub trait ResumeHandle {
    unsafe fn resume(self);
}

/// Abstract executor definition.
///
/// An executor is a per-replica execution unit of a process.
/// There exists an 1:M relationship (a process can have many executor).
///
/// # Naming
/// Some operating-systems (K42, Nemesis, Barrelfish etc.) would call this
/// a dispatcher, we avoid the term because it overlaps with the node-replication
/// dispatch trait.
pub trait Executor {
    type Resumer: ResumeHandle;

    fn start(&mut self) -> Self::Resumer;
    fn resume(&self) -> Self::Resumer;
    fn upcall(&mut self, vector: u64, exception: u64) -> Self::Resumer;
    fn maybe_switch_vspace(&self);
}
