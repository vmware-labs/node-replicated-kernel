// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Generic system call abstraction

use core::fmt::{Debug, LowerHex};

use kpi::{FileOperation, ProcessOperation, SystemCall, SystemOperation, VSpaceOperation};
use log::{error, trace};

use crate::arch::process::user_virt_addr_valid;
use crate::error::{KError, KResult};
use crate::fs::cnrfs;

/// FileOperation: Arch specific implementations
pub(crate) trait FsDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn open(&self, path: W, len: W, flags: W, modes: W) -> KResult<(W, W)>;
    fn read(&self, fd: W, buffer: W, len: W) -> KResult<(W, W)>;
    fn write(&self, fd: W, buffer: W, len: W) -> KResult<(W, W)>;
    fn read_at(&self, fd: W, buffer: W, len: W, offset: W) -> KResult<(W, W)>;
    fn write_at(&self, fd: W, buffer: W, len: W, offset: W) -> KResult<(W, W)>;
    fn close(&self, fd: W) -> KResult<(W, W)>;
    fn get_info(&self, name: W, len: W) -> KResult<(W, W)>;
    fn delete(&self, name: W, len: W) -> KResult<(W, W)>;
    fn file_rename(&self, oldname: W, oldlen: W, newname: W, newlen: W) -> KResult<(W, W)>;
    fn mkdir(&self, pathname: W, len: W, modes: W) -> KResult<(W, W)>;
}

/// Parsed and validated arguments of the file system calls.
enum FileOperationArgs<W> {
    Open(W, W, W, W),
    Read(W, W, W),
    Write(W, W, W),
    ReadAt(W, W, W, W),
    WriteAt(W, W, W, W),
    Close(W),
    GetInfo(W, W),
    Delete(W, W),
    FileRename(W, W, W, W),
    MkDir(W, W, W),
}

impl<W: Into<u64> + LowerHex + Debug + Copy + Clone> FileOperationArgs<W> {
    /// Validate/check the arguments for the FileOperation calls.
    ///
    /// Returns an error if the arguments are invalid.
    fn validate(arg1: W, arg2: W, arg3: W, arg4: W, arg5: W) -> Result<Self, KError> {
        let op = FileOperation::new(arg1.into())
            .ok_or(KError::InvalidFileOperation { a: arg1.into() })?;

        match op {
            FileOperation::Open => Ok(Self::Open(arg2, arg3, arg4, arg5)),
            FileOperation::Read => Ok(Self::Read(arg2, arg3, arg4)),
            FileOperation::Write => Ok(Self::Write(arg2, arg3, arg4)),
            FileOperation::ReadAt => Ok(Self::ReadAt(arg2, arg3, arg4, arg5)),
            FileOperation::WriteAt => Ok(Self::WriteAt(arg2, arg3, arg4, arg5)),
            FileOperation::Close => Ok(Self::Close(arg2)),
            FileOperation::GetInfo => Ok(Self::GetInfo(arg2, arg3)),
            FileOperation::Delete => Ok(Self::Delete(arg2, arg3)),
            FileOperation::FileRename => Ok(Self::FileRename(arg2, arg3, arg4, arg5)),
            FileOperation::MkDir => Ok(Self::MkDir(arg2, arg3, arg4)),
        }
    }
}

/// ProcessOperation: Arch specific implementations
pub(crate) trait ProcessDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn log(&self, buffer_arg: W, len: W) -> KResult<(W, W)>;
    fn get_vcpu_area(&self) -> KResult<(W, W)>;
    fn allocate_vector(&self, vector: W, core: W) -> KResult<(W, W)>;
    fn get_process_info(&self, vaddr_buf: W, vaddr_buf_len: W) -> KResult<(W, W)>;
    fn request_core(&self, core_id: W, entry_point: W) -> KResult<(W, W)>;
    fn allocate_physical(&self, page_size: W, affinity: W) -> KResult<(W, W)>;
    fn exit(&self, code: W) -> KResult<(W, W)>;
}

/// Parsed and validated arguments of the process system calls.
enum ProcessOperationArgs<W> {
    Exit(W),
    Log(W, W),
    GetVCpuArea,
    AllocateVector(W, W),
    GetProcessInfo(W, W),
    RequestCore(W, W),
    AllocatePhysical(W, W),
}

impl<W: Into<u64> + LowerHex + Debug + Copy + Clone> ProcessOperationArgs<W> {
    /// Validate/check the arguments for the ProcessOperation calls.
    ///
    /// Returns an error if the arguments are invalid.
    fn validate(arg1: W, arg2: W, arg3: W) -> Result<Self, KError> {
        match ProcessOperation::new(arg1.into())
            .ok_or(KError::InvalidProcessOperation { a: arg1.into() })?
        {
            ProcessOperation::Log => Ok(Self::Log(arg2, arg3)),
            ProcessOperation::GetVCpuArea => Ok(Self::GetVCpuArea),
            ProcessOperation::AllocateVector => Ok(Self::AllocateVector(arg2, arg3)),
            ProcessOperation::Exit => Ok(Self::Exit(arg2)),
            ProcessOperation::GetProcessInfo => Ok(Self::GetProcessInfo(arg2, arg3)),
            ProcessOperation::RequestCore => Ok(Self::RequestCore(arg2, arg3)),
            ProcessOperation::AllocatePhysical => Ok(Self::AllocatePhysical(arg2, arg3)),
            ProcessOperation::SubscribeEvent => {
                error!("SubscribeEvent is not implemented");
                Err(KError::InvalidProcessOperation { a: arg1.into() })
            }
        }
    }
}

/// VSpaceOperation: Arch specific implementations
pub(crate) trait VSpaceDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn map_mem(&self, base: W, size: W) -> KResult<(W, W)>;
    fn map_pmem(&self, base: W, size: W) -> KResult<(W, W)>;
    fn map_device(&self, base: W, size: W) -> KResult<(W, W)>;
    fn map_frame_id(&self, base: W, frame_id: W) -> KResult<(W, W)>;
    fn unmap_mem(&self, base: W) -> KResult<(W, W)>;
    fn unmap_pmem(&self, base: W) -> KResult<(W, W)>;
    fn identify(&self, addr: W) -> KResult<(W, W)>;
}

/// Parsed and validated arguments of the vspace system calls.
enum VSpaceOperationArgs<W> {
    MapMem(W, W),
    UnmapMem(W),
    MapDevice(W, W),
    MapMemFrame(W, W),
    Identify(W),
    MapPMem(W, W),
    UnmapPMem(W),
}

impl<W: Into<u64> + LowerHex + Debug + Copy + Clone> VSpaceOperationArgs<W> {
    /// Validate/check the arguments for the VSpaceOperation calls.
    ///
    /// Returns an error if the arguments are invalid.
    fn validate(arg1: W, arg2: W, arg3: W) -> Result<Self, KError> {
        let op = VSpaceOperation::new(arg1.into())
            .ok_or(KError::InvalidVSpaceOperation { a: arg1.into() })?;

        match op {
            VSpaceOperation::MapMem => Ok(Self::MapMem(arg2, arg3)),
            VSpaceOperation::MapPMem => Ok(Self::MapPMem(arg2, arg3)),
            VSpaceOperation::MapDevice => Ok(Self::MapDevice(arg2, arg3)),
            VSpaceOperation::MapMemFrame => Ok(Self::MapMemFrame(arg2, arg3)),
            VSpaceOperation::UnmapMem => Ok(Self::UnmapMem(arg2)),
            VSpaceOperation::UnmapPMem => Ok(Self::UnmapPMem(arg2)),
            VSpaceOperation::Identify => Ok(Self::Identify(arg2)),
        }
    }
}

/// SystemOperation: Arch specific implementations
pub(crate) trait SystemDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn get_hardware_threads(&self, vbuf_base: W, vbuf_len: W) -> KResult<(W, W)>;
    fn get_stats(&self) -> KResult<(W, W)>;
    fn get_core_id(&self) -> KResult<(W, W)>;
}

/// Parsed and validated arguments of the system query system calls.
enum SystemOperationArgs<W> {
    GetHardwareThreads(W, W),
    Stats,
    GetCoreID,
}

impl<W: Into<u64> + LowerHex + Debug + Copy + Clone> SystemOperationArgs<W> {
    /// Validate/check the arguments for the SystemOperation calls.
    ///
    /// Returns an error if the arguments are invalid.
    fn validate(arg1: W, arg2: W, arg3: W) -> Result<Self, KError> {
        let op = SystemOperation::new(arg1.into())
            .ok_or(KError::InvalidSystemOperation { a: arg1.into() })?;

        match op {
            SystemOperation::GetHardwareThreads => Ok(Self::GetHardwareThreads(arg2, arg3)),
            SystemOperation::Stats => Ok(Self::Stats),
            SystemOperation::GetCoreID => Ok(Self::GetCoreID),
        }
    }
}

/// [`SystemCall::Test`] stuff.
pub(crate) trait TestDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone> {
    fn test(&self, nargs: W, arg1: W, arg2: W, arg3: W, arg4: W) -> KResult<(W, W)>;
}

/// Generic system call dispatch trait.
///
/// This should be implemented for a specific architecture. The generic `W`
/// should probably be set to whatever gets transmitted as the arguments of the
/// syscall. The arch specific code that handles incoming system calls should
/// call `handle` to dispatch user-space requests to the appropriate handler
/// functions.
pub(crate) trait SystemCallDispatch<W: Into<u64> + LowerHex + Debug + Copy + Clone>:
    VSpaceDispatch<W> + FsDispatch<W> + SystemDispatch<W> + ProcessDispatch<W> + TestDispatch<W>
{
    fn handle(&self, function: W, arg1: W, arg2: W, arg3: W, arg4: W, arg5: W) -> KResult<(W, W)> {
        match SystemCall::new(function.into())
            .ok_or(KError::InvalidSyscallArgument1 { a: function.into() })?
        {
            SystemCall::System => self.system(arg1, arg2, arg3),
            SystemCall::Process => self.process(arg1, arg2, arg3),
            SystemCall::VSpace => self.vspace(arg1, arg2, arg3),
            SystemCall::FileIO => self.fileio(arg1, arg2, arg3, arg4, arg5),
            SystemCall::Test => self.test(arg1, arg2, arg3, arg4, arg5),
        }
    }

    fn system(&self, arg1: W, arg2: W, arg3: W) -> KResult<(W, W)> {
        use SystemOperationArgs::*;
        match SystemOperationArgs::validate(arg1, arg2, arg3)? {
            GetHardwareThreads(vbuf_base, vbuf_len) => {
                self.get_hardware_threads(vbuf_base, vbuf_len)
            }
            Stats => self.get_stats(),
            GetCoreID => self.get_core_id(),
        }
    }

    fn process(&self, arg1: W, arg2: W, arg3: W) -> KResult<(W, W)> {
        use ProcessOperationArgs as Poa;

        match ProcessOperationArgs::validate(arg1, arg2, arg3)? {
            Poa::Log(buffer_arg, len) => self.log(buffer_arg, len),
            Poa::GetVCpuArea => self.get_vcpu_area(),
            Poa::AllocateVector(vector, core) => self.allocate_vector(vector, core),
            Poa::Exit(code) => self.exit(code),
            Poa::GetProcessInfo(vaddr_buf, vaddr_len) => {
                self.get_process_info(vaddr_buf, vaddr_len)
            }
            Poa::RequestCore(core_id, entry_point) => self.request_core(core_id, entry_point),
            Poa::AllocatePhysical(page_size, affinity) => {
                self.allocate_physical(page_size, affinity)
            }
        }
    }

    fn vspace(&self, arg1: W, arg2: W, arg3: W) -> KResult<(W, W)> {
        use VSpaceOperationArgs::*;
        trace!("vspace({:#x}, {:#x}, {:#x})", arg1, arg2, arg3);
        match VSpaceOperationArgs::validate(arg1, arg2, arg3)? {
            MapMem(base, size) => self.map_mem(base, size),
            MapPMem(base, size) => self.map_pmem(base, size),
            MapDevice(base, size) => self.map_device(base, size),
            MapMemFrame(base, frame_id) => self.map_frame_id(base, frame_id),
            UnmapMem(base) => self.unmap_mem(base),
            UnmapPMem(base) => self.unmap_pmem(base),
            Identify(base) => self.identify(base),
        }
    }

    fn fileio(&self, arg1: W, arg2: W, arg3: W, arg4: W, arg5: W) -> KResult<(W, W)> {
        use FileOperationArgs::*;
        match FileOperationArgs::validate(arg1, arg2, arg3, arg4, arg5)? {
            Open(path, len, flags, modes) => self.open(path, len, flags, modes),
            Read(fd, buffer, len) => self.read(fd, buffer, len),
            Write(fd, buffer, len) => self.write(fd, buffer, len),
            ReadAt(fd, buffer, len, offset) => self.read_at(fd, buffer, len, offset),
            WriteAt(fd, buffer, len, offset) => self.write_at(fd, buffer, len, offset),
            Close(fd) => self.close(fd),
            GetInfo(name, len) => self.get_info(name, len),
            Delete(name, len) => self.delete(name, len),
            FileRename(oldname, oldlen, newname, newlen) => {
                self.file_rename(oldname, oldlen, newname, newlen)
            }
            MkDir(pathname, len, modes) => self.mkdir(pathname, len, modes),
        }
    }
}

impl<T> TestDispatch<u64> for T {
    fn test(
        &self,
        nargs: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
    ) -> Result<(u64, u64), KError> {
        match nargs {
            0 => Ok((1, 2)),
            1 => Ok((arg1, arg1 + 1)),
            2 => {
                if arg1 < arg2 {
                    let res = arg1 * arg2;
                    Ok((res, res + 1))
                } else {
                    Err(KError::InvalidSyscallTestArg2)
                }
            }
            3 => {
                if arg1 < arg2 && arg2 < arg3 {
                    let res = arg1 * arg2 * arg3;
                    Ok((res, res + 1))
                } else {
                    Err(KError::InvalidSyscallTestArg3)
                }
            }
            4 => {
                let res = arg1 * arg2 * arg3 * arg4;
                if arg1 < arg2 && arg2 < arg3 && arg3 < arg4 {
                    Ok((res, res + 1))
                } else {
                    Err(KError::InvalidSyscallTestArg4)
                }
            }
            _ => Err(KError::InvalidSyscallArgument1 { a: nargs }),
        }
    }
}

/// The canonical system call dispatch handler for architectures that want to
/// use the CNR based FS.
pub(crate) trait CnrFsDispatch {}

impl<T: CnrFsDispatch> FsDispatch<u64> for T {
    fn open(&self, pathname: u64, len: u64, flags: u64, modes: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, pathname, len)?;
        cnrfs::MlnrKernelNode::map_fd(pid, pathname, flags, modes)
    }

    fn read(&self, fd: u64, buffer: u64, len: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::Read, pid, fd, buffer, len, -1)
    }

    fn write(&self, fd: u64, buffer: u64, len: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::Write, pid, fd, buffer, len, -1)
    }

    fn read_at(&self, fd: u64, buffer: u64, len: u64, offset: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::ReadAt, pid, fd, buffer, len, offset as i64)
    }

    fn write_at(&self, fd: u64, buffer: u64, len: u64, offset: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        cnrfs::MlnrKernelNode::file_io(FileOperation::WriteAt, pid, fd, buffer, len, offset as i64)
    }

    fn close(&self, fd: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        cnrfs::MlnrKernelNode::unmap_fd(pid, fd)
    }

    fn get_info(&self, name: u64, len: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, name, len)?;
        cnrfs::MlnrKernelNode::file_info(pid, name)
    }

    fn delete(&self, name: u64, len: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, name, len)?;
        cnrfs::MlnrKernelNode::file_delete(pid, name)
    }

    fn file_rename(
        &self,
        oldname: u64,
        oldlen: u64,
        newname: u64,
        newlen: u64,
    ) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, oldname, oldlen)?;
        let _r = user_virt_addr_valid(pid, newname, newlen)?;
        cnrfs::MlnrKernelNode::file_rename(pid, oldname, newname)
    }

    fn mkdir(&self, pathname: u64, len: u64, modes: u64) -> Result<(u64, u64), KError> {
        let pid = crate::arch::process::current_pid()?;
        let _r = user_virt_addr_valid(pid, pathname, len)?;
        cnrfs::MlnrKernelNode::mkdir(pid, pathname, modes)
    }
}
