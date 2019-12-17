//! A dummy process implementation for the unix platform.
use alloc::boxed::Box;

use crate::arch::Module;
use crate::memory::Frame;
use crate::process::{Executor, Pid, Process, ProcessError, ResumeHandle};

use super::vspace::VSpace;

pub struct UnixProcess {
    vspace: VSpace,
}

#[derive(Copy, Clone, Debug)]
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
    type A = VSpace;

    fn new(_module: &Module, pid: Pid) -> Result<Self, ProcessError> {
        Ok(UnixProcess {
            vspace: VSpace::new()
        })
    }

    fn try_reserve_executors(
        &self,
        how_many: usize,
        affinity: topology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError> {
        Ok(())
    }

    fn allocate_executors(&mut self, frame: Frame) -> Result<(), ProcessError> {
        Ok(())
    }

    fn vspace(&mut self) -> &mut Self::A {
        &mut self.vspace
    }

    fn get_executor(&mut self, for_region: topology::NodeId) -> Result<Box<Self::E>, ProcessError> {
        Ok(Box::new(UnixThread {}))
    }

}
