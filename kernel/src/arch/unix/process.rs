//! A dummy process implementation for the unix platform.
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};
use x86::bits64::paging::*;
use x86::bits64::rflags;

use crate::arch::Module;
use crate::fs::Fd;
use crate::memory::Frame;
use crate::process::{Executor, Pid, Process, ProcessError, ResumeHandle};

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
        unsafe {
            rflags::stac();
            &*self.value
        }
    }
}

impl<T> DerefMut for UserPtr<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe {
            rflags::stac();
            &mut *self.value
        }
    }
}

impl<T> Drop for UserPtr<T> {
    fn drop(&mut self) {
        unsafe { rflags::clac() };
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
        unsafe {
            rflags::stac();
            &self.value
        }
    }
}

impl<T> DerefMut for UserValue<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            rflags::stac();
            &mut self.value
        }
    }
}

impl<T> Drop for UserValue<T> {
    fn drop(&mut self) {
        unsafe { rflags::clac() };
    }
}

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
