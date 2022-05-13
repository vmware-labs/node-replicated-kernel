// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Generic system call abstraction

use core::fmt::{Debug, LowerHex};

use kpi::{FileOperation, ProcessOperation, SystemCall, SystemOperation, VSpaceOperation};
use log::{error, trace};

#[cfg(not(feature = "rackscale-lwk"))]
use crate::arch::process::user_virt_addr_valid;
use crate::cnrfs;
use crate::error::KError;
#[cfg(not(feature = "rackscale-lwk"))]
use crate::kcb::ArchSpecificKcb;

/// FileOperation: Arch specific implementations
pub trait FsDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn fs_open(&self, pathname: W, flags: W, modes: W) -> Result<(W, W), KError>;
    fn fs_read(&self, fd: W, buffer: W, len: W) -> Result<(W, W), KError>;
    fn fs_write(&self, fd: W, buffer: W, len: W) -> Result<(W, W), KError>;
    fn fs_read_at(&self, fd: W, buffer: W, len: W, offset: W) -> Result<(W, W), KError>;
    fn fs_write_at(&self, fd: W, buffer: W, len: W, offset: W) -> Result<(W, W), KError>;
    fn fs_close(&self, fd: W) -> Result<(W, W), KError>;
    fn fs_get_info(&self, name: W, info_ptr: W) -> Result<(W, W), KError>;
    fn fs_delete(&self, name: W) -> Result<(W, W), KError>;
    fn fs_file_rename(&self, oldname: W, newname: W) -> Result<(W, W), KError>;
    fn fs_mkdir(&self, pathname: W, modes: W) -> Result<(W, W), KError>;
}

/// ProcessOperation: Arch specific implementations
pub trait ProcessDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn log(&self, buffer_arg: W, len: W) -> Result<(W, W), KError>;
    fn get_vcpu_area(&self) -> Result<(W, W), KError>;
    fn allocate_vector(&self, vector: W, core: W) -> Result<(W, W), KError>;
    fn get_process_info(&self, vaddr_buf: W, vaddr_buf_len: W) -> Result<(W, W), KError>;
    fn request_core(&self, core_id: W, entry_point: W) -> Result<(W, W), KError>;
    fn allocate_physical(&self, page_size: W, affinity: W) -> Result<(W, W), KError>;
    fn exit(&self, code: W) -> Result<(W, W), KError>;
}

/// VSpaceOperation: Arch specific implementations
pub trait VSpaceDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn map_mem(&self, base: W, size: W) -> Result<(W, W), KError>;
    fn map_pmem(&self, base: W, size: W) -> Result<(W, W), KError>;
    fn map_device(&self, base: W, size: W) -> Result<(W, W), KError>;
    fn map_frame_id(&self, base: W, frame_id: W) -> Result<(W, W), KError>;
    fn unmap_mem(&self, base: W) -> Result<(W, W), KError>;
    fn unmap_pmem(&self, base: W) -> Result<(W, W), KError>;
    fn identify(&self, addr: W) -> Result<(W, W), KError>;
}

/// SystemOperation: Arch specific implementations
pub trait SystemDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn get_hardware_threads(&self, vbuf_base: W, vbuf_len: W) -> Result<(W, W), KError>;
    fn get_stats(&self) -> Result<(W, W), KError>;
    fn get_core_id(&self) -> Result<(W, W), KError>;
}

/// Generic system call dispatch trait.
///
/// This should be implemented for a specific architecture. The generic `W`
/// should probably be set to whatever gets transmitted as the arguments of the
/// syscall. The arch specific code that handles incoming system calls should
/// call `handle` to dispatch user-space requests to the appropriate handler
/// functions.
pub trait SystemCallDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone>:
    VSpaceDispatch<W> + FsDispatch<W> + SystemDispatch<W> + ProcessDispatch<W>
{
    fn handle(
        &self,
        function: W,
        arg1: W,
        arg2: W,
        arg3: W,
        arg4: W,
        arg5: W,
    ) -> Result<(W, W), KError> {
        match SystemCall::new(function.into()) {
            SystemCall::System => self.system(arg1, arg2, arg3),
            SystemCall::Process => self.process(arg1, arg2, arg3),
            SystemCall::VSpace => self.vspace(arg1, arg2, arg3),
            SystemCall::FileIO => self.fileio(arg1, arg2, arg3, arg4, arg5),
            SystemCall::Test => self.test(arg1, arg2, arg3, arg4, arg5),
            _ => Err(KError::InvalidSyscallArgument1 { a: function.into() }),
        }
    }

    fn system(&self, arg1: W, arg2: W, arg3: W) -> Result<(W, W), KError> {
        let op = SystemOperation::from(arg1.into());
        match op {
            SystemOperation::GetHardwareThreads => self.get_hardware_threads(arg2, arg3),
            SystemOperation::Stats => self.get_stats(),
            SystemOperation::GetCoreID => self.get_core_id(),
            SystemOperation::Unknown => Err(KError::InvalidSystemOperation { a: arg1.into() }),
        }
    }

    fn process(&self, arg1: W, arg2: W, arg3: W) -> Result<(W, W), KError> {
        let op = ProcessOperation::from(arg1.into());
        match op {
            ProcessOperation::Log => self.log(arg2, arg3),
            ProcessOperation::GetVCpuArea => self.get_vcpu_area(),
            ProcessOperation::AllocateVector => self.allocate_vector(arg2, arg3),
            ProcessOperation::Exit => self.exit(arg2),
            ProcessOperation::GetProcessInfo => self.get_process_info(arg2, arg3),
            ProcessOperation::RequestCore => self.request_core(arg2, arg3),
            ProcessOperation::AllocatePhysical => self.allocate_physical(arg2, arg3),
            ProcessOperation::SubscribeEvent => {
                error!("SubscribeEvent not implemented");
                Err(KError::InvalidProcessOperation { a: arg1.into() })
            }
            ProcessOperation::Unknown => Err(KError::InvalidProcessOperation { a: arg1.into() }),
        }
    }

    fn vspace(&self, arg1: W, arg2: W, arg3: W) -> Result<(W, W), KError> {
        let op = VSpaceOperation::from(arg1.into());
        trace!("vspace({:?}, {:#x}, {:#x}, {:#x})", op, arg1, arg2, arg3);
        match op {
            VSpaceOperation::MapMem => self.map_mem(arg2, arg3),
            VSpaceOperation::MapPMem => self.map_pmem(arg2, arg3),
            VSpaceOperation::MapDevice => self.map_device(arg2, arg3),
            VSpaceOperation::MapMemFrame => self.map_frame_id(arg2, arg3),
            VSpaceOperation::UnmapMem => self.unmap_mem(arg2),
            VSpaceOperation::UnmapPMem => self.unmap_pmem(arg2),
            VSpaceOperation::Identify => self.identify(arg2),
            VSpaceOperation::Unknown => {
                error!("Got an invalid VSpaceOperation {:?}.", arg1);
                Err(KError::InvalidVSpaceOperation { a: arg1.into() })
            }
        }
    }

    fn fileio(&self, arg1: W, arg2: W, arg3: W, arg4: W, arg5: W) -> Result<(W, W), KError> {
        let op = FileOperation::from(arg1.into());
        match op {
            FileOperation::Open => self.fs_open(arg2, arg3, arg4),
            FileOperation::Read => self.fs_read(arg2, arg3, arg4),
            FileOperation::Write => self.fs_write(arg2, arg3, arg4),
            FileOperation::ReadAt => self.fs_read_at(arg2, arg3, arg4, arg5),
            FileOperation::WriteAt => self.fs_write_at(arg2, arg3, arg4, arg5),
            FileOperation::Close => self.fs_close(arg2),
            FileOperation::GetInfo => self.fs_get_info(arg2, arg3),
            FileOperation::Delete => self.fs_delete(arg2),
            FileOperation::FileRename => self.fs_file_rename(arg2, arg3),
            FileOperation::MkDir => self.fs_mkdir(arg2, arg3),
            FileOperation::Unknown => Err(KError::NotSupported),
        }
    }

    /// [`SystemCall::Test`] Should be directly implemented as an arch-specific call.
    fn test(&self, nargs: W, arg1: W, arg2: W, arg3: W, arg4: W) -> Result<(W, W), KError>;
}

/// The canonical system call dispatch handler for architectures that want to
/// use the CNR based FS.
pub trait CnrFsDispatch {}

impl<T: CnrFsDispatch> FsDispatch<u64> for T {
    fn fs_open(&self, pathname: u64, flags: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, pathname, 0)?;
        cnrfs::MlnrKernelNode::map_fd(pid, pathname, flags, modes)
    }

    fn fs_read(&self, fd: u64, buffer: u64, len: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::Read, pid, fd, buffer, len, -1)
    }

    fn fs_write(&self, fd: u64, buffer: u64, len: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::Write, pid, fd, buffer, len, -1)
    }

    fn fs_read_at(
        &self,
        fd: u64,
        buffer: u64,
        len: u64,
        offset: u64,
    ) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::ReadAt, pid, fd, buffer, len, offset as i64)
    }

    fn fs_write_at(
        &self,
        fd: u64,
        buffer: u64,
        len: u64,
        offset: u64,
    ) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::WriteAt, pid, fd, buffer, len, offset as i64)
    }

    fn fs_close(&self, fd: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        cnrfs::MlnrKernelNode::unmap_fd(pid, fd)
    }

    fn fs_get_info(&self, name: u64, info_ptr: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, name, 0)?;
        cnrfs::MlnrKernelNode::file_info(pid, name, info_ptr)
    }

    fn fs_delete(&self, name: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, name, 0)?;
        cnrfs::MlnrKernelNode::file_delete(pid, name)
    }

    fn fs_file_rename(&self, oldname: u64, newname: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, oldname, 0)?;
        let _r = user_virt_addr_valid(pid, newname, 0)?;
        cnrfs::MlnrKernelNode::file_rename(pid, oldname, newname)
    }

    fn fs_mkdir(&self, pathname: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, pathname, 0)?;
        cnrfs::MlnrKernelNode::mkdir(pid, pathname, modes)
    }
}
