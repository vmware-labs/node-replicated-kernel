//! Generic process traits
use alloc::boxed::Box;
use alloc::string::{String, ToString};

use custom_error::custom_error;

use crate::arch::Module;
use crate::fs::Fd;
use crate::memory::vspace::AddressSpace;
use crate::memory::Frame;

/// Process ID.
pub type Pid = u64;

/// Executor ID.
pub type Eid = u64;

custom_error! {
#[derive(PartialEq, Clone)]
pub ProcessError
    ProcessCreate{desc: String}  = "Unable to create process: {desc}",
    NoProcessFoundForPid = "No process was associated with the given Pid.",
    UnableToLoad = "Couldn't load process, invalid ELF file?",
    NoExecutorAllocated = "We never allocated executors for this affinity region and process (need to fill cache).",
    ExecutorCacheExhausted = "The executor cache for given affinity is empty (need to refill)",
    InvalidGlobalThreadId = "Specified an invalid core",
}

impl From<&str> for ProcessError {
    fn from(_err: &str) -> Self {
        ProcessError::UnableToLoad
    }
}

/// Abstract definition of a process.
pub trait Process {
    type E: Executor + Copy;
    type A: AddressSpace;

    fn new(module: &Module, pid: Pid) -> Result<Self, ProcessError>
    where
        Self: core::marker::Sized;

    fn try_reserve_executors(
        &self,
        how_many: usize,
        affinity: topology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError>;
    fn allocate_executors(&mut self, frame: Frame) -> Result<(), ProcessError>;

    fn vspace(&mut self) -> &mut Self::A;

    fn get_executor(&mut self, for_region: topology::NodeId) -> Result<Box<Self::E>, ProcessError>;

    fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)>;

    fn deallocate_fd(&mut self, fd: usize) -> usize;

    fn get_fd(&mut self, index: usize) -> &mut Fd;

    fn pinfo(&self) -> &kpi::process::ProcessInfo;
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

    fn id(&self) -> Eid;
    fn start(&mut self) -> Self::Resumer;
    fn resume(&self) -> Self::Resumer;
    fn upcall(&mut self, vector: u64, exception: u64) -> Self::Resumer;
    fn maybe_switch_vspace(&self);
}
