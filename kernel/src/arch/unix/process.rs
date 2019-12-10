//! A dummy process implementation for the unix platform.

use crate::arch::Module;
use crate::process::{Executor, Process, ProcessError, ResumeHandle};

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

    fn new(_module: &Module) -> Result<Self, ProcessError> {
        Ok(UnixProcess {})
    }

    fn add_dispatcher(&mut self) -> Self::E {
        UnixThread {}
    }

    fn remove_dispatcher(&mut self, _d: Self::E) {}
}
