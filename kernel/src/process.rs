//! Generic process trait
use core::marker::PhantomData;

use crate::arch::Module;

#[derive(Debug)]
pub enum ProcessError {
    UnableToLoad,
}

/// Abstract definition of a process.
pub trait Process {
    type E: Executor;

    fn new(module: &Module) -> Result<Self, ProcessError>
    where
        Self: core::marker::Sized;

    fn add_dispatcher(&mut self) -> Self::E;
    fn remove_dispatcher(&mut self, d: Self::E);
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
