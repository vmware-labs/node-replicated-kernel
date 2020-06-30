//! A dummy process implementation for the unix platform.
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use kpi::process::FrameId;

use crate::arch::Module;
use crate::error::KError;
use crate::fs::Fd;
use crate::memory::{Frame, VAddr};
use crate::process::{Eid, Executor, Pid, Process, ProcessError, ResumeHandle};

use super::debug;
use super::vspace::VSpace;

/// TODO: This code is same as x86_64 process. Can we remove it?
pub struct UserPtr<T> {
    value: *mut T,
}

impl<T> UserPtr<T> {
    pub fn new(pointer: *mut T) -> UserPtr<T> {
        UserPtr { value: pointer }
    }

    pub fn vaddr(&self) -> VAddr {
        VAddr::from(self.value as u64)
    }
}

impl<T> Deref for UserPtr<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.value }
    }
}

impl<T> DerefMut for UserPtr<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.value }
    }
}

pub struct UserValue<T> {
    value: T,
}

impl<T> UserValue<T> {
    pub fn new(pointer: T) -> UserValue<T> {
        UserValue { value: pointer }
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        unsafe { core::mem::transmute(&self.value) }
    }
}

impl<T> Deref for UserValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for UserValue<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UserSlice<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> UserSlice<'a> {
    pub fn from_slice(buffer: &'a mut [u8]) -> Self {
        UserSlice { buffer }
    }

    pub fn new(base: u64, len: usize) -> UserSlice<'a> {
        let mut user_ptr = VAddr::from(base);
        let slice_ptr = UserPtr::new(&mut user_ptr);
        let user_slice: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(slice_ptr.as_mut_ptr(), len) };
        UserSlice { buffer: user_slice }
    }
}

impl<'a> Deref for UserSlice<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &*self.buffer
    }
}

impl<'a> DerefMut for UserSlice<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.buffer
    }
}

pub struct UnixProcess {
    vspace: VSpace,
    fd: Fd,
    pinfo: kpi::process::ProcessInfo,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct UnixThread {
    eid: Eid,
}

pub struct UnixResumeHandle {}

impl ResumeHandle for UnixResumeHandle {
    unsafe fn resume(self) -> ! {
        debug::shutdown(super::ExitReason::Ok)
    }
}

impl Executor for UnixThread {
    type Resumer = UnixResumeHandle;

    fn id(&self) -> Eid {
        self.eid
    }

    fn start(&self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn resume(&self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn upcall(&self, _vector: u64, _exception: u64) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn new_core_upcall(&self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn maybe_switch_vspace(&self) {}

    fn vcpu_kernel(&self) -> *mut kpi::arch::VirtualCpu {
        core::ptr::null_mut()
    }
}

impl Process for UnixProcess {
    type E = UnixThread;
    type A = VSpace;

    fn new(
        _module: &Module,
        _pid: Pid,
        _writable_sections: Vec<Frame>,
    ) -> Result<Self, ProcessError> {
        Ok(UnixProcess {
            vspace: VSpace::new(),
            fd: Default::default(),
            pinfo: Default::default(),
        })
    }

    fn try_reserve_executors(
        &self,
        _how_many: usize,
        _affinity: topology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError> {
        Ok(())
    }

    fn allocate_executors(&mut self, _frame: Frame) -> Result<usize, ProcessError> {
        Ok(0)
    }

    fn vspace_mut(&mut self) -> &mut Self::A {
        &mut self.vspace
    }

    fn vspace(&self) -> &VSpace {
        &self.vspace
    }

    fn get_executor(
        &mut self,
        _for_region: topology::NodeId,
    ) -> Result<Box<Self::E>, ProcessError> {
        Ok(Box::new(UnixThread::default()))
    }

    fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)> {
        Some((1, &mut self.fd))
    }

    fn deallocate_fd(&mut self, _fd: usize) -> usize {
        0
    }

    fn get_fd(&self, _index: usize) -> &Fd {
        &self.fd
    }

    fn pinfo(&self) -> &kpi::process::ProcessInfo {
        &self.pinfo
    }

    fn add_frame(&mut self, _frame: Frame) -> Result<FrameId, ProcessError> {
        Err(ProcessError::InvalidFrameId)
    }

    fn get_frame(&mut self, _frame_id: FrameId) -> Result<Frame, ProcessError> {
        Err(ProcessError::InvalidFrameId)
    }
}

pub fn spawn(binary: &'static str) -> Result<Pid, KError> {
    Err(KError::NotSupported)
}
