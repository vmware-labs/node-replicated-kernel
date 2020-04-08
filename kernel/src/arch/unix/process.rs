//! A dummy process implementation for the unix platform.
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

use crate::arch::Module;
use crate::fs::Fd;
use crate::memory::{Frame, VAddr};
use crate::process::{Eid, Executor, Pid, Process, ProcessError, ResumeHandle};

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

pub struct UserSlice<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> UserSlice<'a> {
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
    unsafe fn resume(self) {}
}

impl Executor for UnixThread {
    type Resumer = UnixResumeHandle;

    fn id(&self) -> Eid {
        self.eid
    }

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
            vspace: VSpace::new(),
            fd: Default::default(),
            pinfo: Default::default(),
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
        Ok(Box::new(UnixThread::default()))
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

    fn pinfo(&self) -> &kpi::process::ProcessInfo {
        &self.pinfo
    }
}
