// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Abstraction for system calls to access the global file-system and control interrupts.

use core::convert::TryInto;

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
    /// Opens a file. Returns `fd` if successful; error otherwise.
    pub fn open<T: AsRef<str>>(
        path: T,
        flags: FileFlags,
        modes: FileModes,
    ) -> Result<u64, SystemCallError> {
        let (r, fd) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::Open as u64,
                path.as_ref().as_ptr(),
                path.as_ref().len(),
                u64::from(flags),
                u64::from(modes),
                2
            )
        };

        if r == 0 {
            Ok(fd)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Close a file. This function will remove the file descriptor from the
    /// process. It doesn't do anything to the file.
    pub fn close(fd: u64) -> Result<(), SystemCallError> {
        let r = unsafe { syscall!(SystemCall::FileIO as u64, FileOperation::Close, fd, 1) };

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn read(fd: u64, buffer: &mut [u8]) -> Result<u64, SystemCallError> {
        Fs::fileio(
            FileOperation::Read,
            fd,
            buffer.as_mut_ptr() as u64,
            buffer.len().try_into().unwrap(),
        )
    }

    pub fn write(fd: u64, buffer: &[u8]) -> Result<u64, SystemCallError> {
        Fs::fileio(
            FileOperation::Write,
            fd,
            buffer.as_ptr() as u64,
            buffer.len().try_into().unwrap(),
        )
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

    pub fn read_at(fd: u64, buffer: &mut [u8], offset: i64) -> Result<u64, SystemCallError> {
        Fs::fileio_at(
            FileOperation::ReadAt,
            fd,
            buffer.as_mut_ptr() as u64,
            buffer.len().try_into().unwrap(),
            offset,
        )
    }

    pub fn write_at(fd: u64, buffer: &[u8], offset: i64) -> Result<u64, SystemCallError> {
        Fs::fileio_at(
            FileOperation::WriteAt,
            fd,
            buffer.as_ptr() as u64,
            buffer.len().try_into().unwrap(),
            offset,
        )
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
                _ => unreachable!("write_at received non *-at op"),
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
    pub fn getinfo<T: AsRef<str>>(path: T) -> Result<FileInfo, SystemCallError> {
        let (r, ftype, fsize) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::GetInfo,
                path.as_ref().as_ptr(),
                path.as_ref().len(),
                3
            )
        };

        if r == 0 {
            Ok(FileInfo { ftype, fsize })
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Delete a file given by `name`.
    pub fn delete<T: AsRef<str>>(path: T) -> Result<(), SystemCallError> {
        let (r, is_deleted) = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::Delete as u64,
                path.as_ref().as_ptr(),
                path.as_ref().len(),
                2
            )
        };

        if r == 0 && is_deleted == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn rename<T: AsRef<str>>(old_name: T, new_name: T) -> Result<(), SystemCallError> {
        let r = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::FileRename,
                old_name.as_ref().as_ptr(),
                old_name.as_ref().len(),
                new_name.as_ref().as_ptr(),
                new_name.as_ref().len(),
                1
            )
        };

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }

    pub fn mkdir_simple<T: AsRef<str>>(path: T, modes: FileModes) -> Result<(), SystemCallError> {
        let r = unsafe {
            syscall!(
                SystemCall::FileIO as u64,
                FileOperation::MkDir,
                path.as_ref().as_ptr(),
                path.as_ref().len(),
                u64::from(modes),
                1
            )
        };

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }
}
