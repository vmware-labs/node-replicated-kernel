//! A dummy process implementation for the unix platform.
use alloc::boxed::Box;

use crate::arch::Module;
use crate::fs::Fd;
use crate::memory::Frame;
use crate::process::{Executor, Pid, Process, ProcessError, ResumeHandle};

use super::vspace::VSpace;

pub struct UnixProcess {
    vspace: VSpace,
    fd: Fd,
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
    type F = Fd;

    fn new(_module: &Module, pid: Pid) -> Result<Self, ProcessError> {
        Ok(UnixProcess {
            vspace: VSpace::new(),
            fd: Default::default(),
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

    fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)> {
        Some((1, &mut self.fd))
    }

    fn deallocate_fd(&mut self, fd: usize) -> usize {
        0
    }

    fn get_fd(&mut self, index: usize) -> &mut Fd {
        &mut self.fd
    }
}
