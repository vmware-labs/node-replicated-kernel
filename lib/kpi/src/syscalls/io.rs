// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Abstraction for system calls to access the global file-system and control interrupts.

use crate::io::*;
use crate::*;

use crate::syscall;

/// System calls related to interrupt routing.
pub struct Irq;

impl Irq {
    /// Manipulate the CPU interrupt alloction table.
    pub fn irqalloc(vec: u64, core: u64) -> Result<(), SystemCallError> {
        let (r, retvec, retcore) = unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::AllocateVector as u64,
                vec,
                core,
                3
            )
        };

        assert_eq!(vec, retvec);
        assert_eq!(core, retcore);

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }
}

/// System calls related to file-systems.
pub struct Fs;

impl Fs {
    /// Create a file. The function internally calls file_open with O_CREAT flag.
    pub fn create(pathname: u64, modes: u64) -> Result<u64, SystemCallError> {
        let flags: u64 = u64::from(FileFlags::O_WRONLY | FileFlags::O_CREAT);
        assert_eq!(flags, 0x202);
        Fs::open(pathname, flags, modes)
    }

    /// Open a file. Return `fd` if successful; error otherwise.
    pub fn open(pathname: u64, flags: u64, modes: u64) -> Result<u64, SystemCallError> {
        let (r, fd) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::Open as u64,
                pathname,
                flags,
                modes,
                2
            )
        };

        if r == 0 {
            Ok(fd)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Close a file. This function will remove the file descriptor from the process.
    /// It doesn't do anything to the file.
    pub fn close(fd: u64) -> Result<u64, SystemCallError> {
        let r = unsafe { syscall!(SystemCall::FileIO as u64, FileOperation::Close, fd, 1) };

        if r == 0 {
            Ok(r)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn read(fd: u64, buffer: u64, len: u64) -> Result<u64, SystemCallError> {
        Fs::fileio(FileOperation::Read, fd, buffer, len)
    }

    pub fn write(fd: u64, buffer: u64, len: u64) -> Result<u64, SystemCallError> {
        Fs::fileio(FileOperation::Write, fd, buffer, len)
    }

    /// Read or write an opened file. `fd` is the file descriptor for the opened file.
    fn fileio(op: FileOperation, fd: u64, buffer: u64, len: u64) -> Result<u64, SystemCallError> {
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let (r, len) =
            unsafe { syscall!(SystemCall::FileIO as u64, op as u64, fd, buffer, len, 2) };

        if r == 0 {
            Ok(len)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn read_at(fd: u64, buffer: u64, len: u64, offset: i64) -> Result<u64, SystemCallError> {
        Fs::fileio_at(FileOperation::ReadAt, fd, buffer, len, offset)
    }

    pub fn write_at(fd: u64, buffer: u64, len: u64, offset: i64) -> Result<u64, SystemCallError> {
        Fs::fileio_at(FileOperation::WriteAt, fd, buffer, len, offset)
    }

    /// Read or write an opened file starting at the offset.
    fn fileio_at(
        op: FileOperation,
        fd: u64,
        buffer: u64,
        len: u64,
        offset: i64,
    ) -> Result<u64, SystemCallError> {
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        if offset == -1 {
            match op {
                FileOperation::ReadAt => return Err(SystemCallError::OffsetError),
                FileOperation::WriteAt => return Fs::fileio(FileOperation::Write, fd, buffer, len),
                _ => unreachable!("write_at received non *-At op"),
            }
        }

        // If read or write is performed at the specific offset.
        let (r, len) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                op as u64,
                fd,
                buffer,
                len,
                offset as u64,
                2
            )
        };

        if r == 0 {
            Ok(len)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Retrieve information about a file.
    pub fn getinfo(name: u64) -> Result<FileInfo, SystemCallError> {
        let fileinfo: FileInfo = Default::default();
        let r = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::GetInfo,
                name as u64,
                &fileinfo as *const FileInfo as u64,
                1
            )
        };

        if r == 0 {
            Ok(fileinfo)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Delete a file given by `name`.
    pub fn delete(name: u64) -> Result<bool, SystemCallError> {
        let (r, is_deleted) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::Delete as u64,
                name,
                2
            )
        };

        if r == 0 && is_deleted == 0 {
            Ok(true)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn write_direct(buffer: u64, len: u64, offset: i64) -> Result<u64, SystemCallError> {
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }
        let mut is_offset = true;
        if offset == -1 {
            is_offset = false;
        }

        // If read or write is performed at the specific offset.
        let (r, len) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::WriteDirect as u64,
                buffer,
                len,
                offset as u64,
                is_offset,
                2
            )
        };

        if r == 0 {
            Ok(len)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn rename(old_name: u64, new_name: u64) -> Result<u64, SystemCallError> {
        let r = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::FileRename,
                old_name,
                new_name,
                1
            )
        };

        if r == 0 {
            Ok(0)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn mkdir_simple(pathname: u64, modes: u64) -> Result<u64, SystemCallError> {
        let r = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::MkDir,
                pathname,
                modes,
                1
            )
        };

        if r == 0 {
            Ok(0)
        } else {
            Err(SystemCallError::from(r))
        }
    }
}
