//! A dummy process implementation for the unix platform.

use crate::arch::Module;
use crate::memory::Frame;
use crate::process::{Executor, Pid, Process, ProcessError, ResumeHandle};

pub struct UnixProcess {}
pub struct UnixThread {}
pub struct UnixResumeHandle {}

impl ResumeHandle for UnixResumeHandle {
    unsafe fn resume(self) {}
}

impl Executor for UnixThread {
    type Resumer = UnixResumeHandle;

    fn start(&mut self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn resume(&self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn upcall(&mut self, _vector: u64, _exception: u64) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn maybe_switch_vspace(&self) {}
}

impl Process for UnixProcess {
    type E = UnixThread;

    fn new(_module: &Module, pid: Pid) -> Result<Self, ProcessError> {
        Ok(UnixProcess {})
    }

    fn try_reserve_executors(
        how_many: usize,
        affinity: topology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError> {
        Ok(())
    }

    fn allocate_executors(&mut self, frame: Frame) -> Result<(), ProcessError> {
        Ok(())
    }
}
