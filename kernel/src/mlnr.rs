#![allow(unused)]

use crate::arch::process::{UserPtr, UserSlice};
use crate::error::KError;
use crate::fs::{
    Buffer, FileDescriptor, FileSystem, FileSystemError, Filename, Flags, Len, Modes, Offset, FD,
};
use crate::memory::VAddr;
use crate::mlnrfs::{fd::FileDesc, MlnrFS, NrLock, MNODE_OFFSET};
use crate::prelude::*;
use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};

use alloc::sync::Arc;
use cnr::{Dispatch, LogMapper, ReplicaToken};
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use kpi::{io::*, FileOperation};

pub struct MlnrKernelNode {
    /// TODO: RwLock should be okay for read-write operations as those ops
    /// perform read() on lock. Make an array of hashmaps to distribute the
    /// load evenly for file-open benchmarks.
    process_map: NrLock<HashMap<Pid, FileDesc>>,
    /// MLNR kernel node primarily replicates the in-memory filesystem.
    fs: MlnrFS,
}

impl Default for MlnrKernelNode {
    fn default() -> Self {
        MlnrKernelNode {
            process_map: NrLock::<HashMap<Pid, FileDesc>>::default(),
            fs: MlnrFS::default(),
        }
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Modify {
    ProcessAdd(Pid),
    ProcessRemove(Pid),
    FileOpen(Pid, String, Flags, Modes),
    FileWrite(Pid, FD, Arc<[u8]>, Len, Offset),
    FileClose(Pid, FD),
    FileDelete(Pid, String),
    FileRename(Pid, String, String),
    MkDir(Pid, String, Modes),
    Invalid,
}

// TODO: Stateless op to log mapping. Maintain some state for correct redirection.
impl LogMapper for Modify {
    fn hash(&self) -> usize {
        match self {
            Modify::ProcessAdd(_pid) => 0,
            Modify::ProcessRemove(_pid) => 0,
            Modify::FileOpen(_pid, _filename, _flags, _modes) => 0,
            Modify::FileWrite(pid, fd, _kernslice, _len, _offset) => {
                match MlnrKernelNode::fd_to_mnode(*pid, *fd) {
                    Ok((mnode, _)) => mnode as usize - MNODE_OFFSET,
                    Err(_) => 0,
                }
            }
            Modify::FileClose(pid, fd) => 0,
            Modify::FileDelete(_pid, _filename) => 0,
            Modify::FileRename(_pid, _oldname, _newname) => 0,
            Modify::MkDir(_pid, _name, _modes) => 0,
            Modify::Invalid => unreachable!("Invalid operation"),
        }
    }
}

impl Default for Modify {
    fn default() -> Self {
        Modify::Invalid
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Access {
    FileRead(Pid, FD, Buffer, Len, Offset),
    FileInfo(Pid, Filename, u64),
    FdToMnode(Pid, FD),
    FileNameToMnode(Pid, Filename),
    Synchronize(usize),
}

//TODO: Stateless op to log mapping. Maintain some state for correct redirection.
impl LogMapper for Access {
    fn hash(&self) -> usize {
        match self {
            Access::FileRead(pid, fd, _buffer, _len, _offser) => {
                match MlnrKernelNode::fd_to_mnode(*pid, *fd) {
                    Ok((mnode, _)) => mnode as usize - MNODE_OFFSET,
                    Err(_) => 0,
                }
            }
            Access::FileInfo(pid, filename, _info_ptr) => {
                match MlnrKernelNode::filename_to_mnode(*pid, *filename) {
                    Ok((mnode, _)) => mnode as usize - MNODE_OFFSET,
                    Err(_) => 0,
                }
            }
            // TODO: Assume that all metadata modifying operations go through log 0.
            Access::FdToMnode(_pid, _fd) => 0,
            Access::FileNameToMnode(_pid, _filename) => 0,
            // Log number start with 1 in CNR, however, replica uses mod
            // operation which starts with 0; hence `log_id - 1`.
            Access::Synchronize(log_id) => (*log_id - 1),
        }
    }
}

#[derive(Clone, Debug)]
pub enum MlnrNodeResult {
    ProcessAdded(Pid),
    FileOpened(FD),
    FileAccessed(Len),
    FileClosed(u64),
    FileDeleted(bool),
    FileInfo(u64),
    FileRenamed(bool),
    DirCreated(bool),
    MappedFileToMnode(u64),
    Synchronized,
}

/// TODO: Most of the functions looks same as in nr.rs. Merge the
/// two and maybe move all the functions to a separate file?
impl MlnrKernelNode {
    pub fn add_process(pid: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Modify::ProcessAdd(pid), *token);
                match &response {
                    Ok(MlnrNodeResult::ProcessAdded(pid)) => Ok((*pid, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(e) => Err(e.clone()),
                }
            })
    }

    pub fn map_fd(pid: Pid, pathname: u64, flags: u64, modes: u64) -> Result<(FD, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename;
                match userptr_to_str(pathname) {
                    Ok(user_str) => filename = user_str,
                    Err(e) => return Err(e.clone()),
                }

                let response =
                    replica.execute_mut(Modify::FileOpen(pid, filename, flags, modes), *token);

                match &response {
                    Ok(MlnrNodeResult::FileOpened(fd)) => Ok((*fd, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_io(
        op: FileOperation,
        pid: Pid,
        fd: u64,
        buffer: u64,
        len: u64,
        offset: i64,
    ) -> Result<(Len, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| match op {
                FileOperation::Write | FileOperation::WriteAt => {
                    let kernslice = KernSlice::new(buffer, len as usize);

                    let response = replica.execute_mut(
                        Modify::FileWrite(pid, fd, kernslice.buffer.clone(), len, offset),
                        *token,
                    );

                    match &response {
                        Ok(MlnrNodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }

                FileOperation::Read | FileOperation::ReadAt => {
                    let response =
                        replica.execute(Access::FileRead(pid, fd, buffer, len, offset), *token);

                    match &response {
                        Ok(MlnrNodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }
                _ => unreachable!(),
            })
    }

    pub fn unmap_fd(pid: Pid, fd: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Modify::FileClose(pid, fd), *token);

                match &response {
                    Ok(MlnrNodeResult::FileClosed(fd)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_delete(pid: Pid, name: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename;
                match userptr_to_str(name) {
                    Ok(user_str) => filename = user_str,
                    Err(e) => return Err(e.clone()),
                }
                let response = replica.execute_mut(Modify::FileDelete(pid, filename), *token);

                match &response {
                    Ok(MlnrNodeResult::FileDeleted(_)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_info(pid: Pid, name: u64, info_ptr: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::FileInfo(pid, name, info_ptr), *token);

                match &response {
                    Ok(MlnrNodeResult::FileInfo(_)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_rename(pid: Pid, oldname: u64, newname: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let oldfilename;
                match userptr_to_str(oldname) {
                    Ok(user_str) => oldfilename = user_str,
                    Err(e) => return Err(e.clone()),
                }

                let newfilename;
                match userptr_to_str(newname) {
                    Ok(user_str) => newfilename = user_str,
                    Err(e) => return Err(e.clone()),
                }

                let response =
                    replica.execute_mut(Modify::FileRename(pid, oldfilename, newfilename), *token);
                match &response {
                    Ok(MlnrNodeResult::FileRenamed(_)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn mkdir(pid: Pid, pathname: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename;
                match userptr_to_str(pathname) {
                    Ok(user_str) => filename = user_str,
                    Err(e) => return Err(e.clone()),
                }

                let response = replica.execute_mut(Modify::MkDir(pid, filename, modes), *token);

                match &response {
                    Ok(MlnrNodeResult::DirCreated(true)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    #[inline(always)]
    pub fn fd_to_mnode(pid: Pid, fd: FD) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::FdToMnode(pid, fd), *token);

                match &response {
                    Ok(MlnrNodeResult::MappedFileToMnode(mnode)) => Ok((*mnode, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    #[inline(always)]
    pub fn filename_to_mnode(pid: Pid, filename: Filename) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::FileNameToMnode(pid, filename), *token);

                match &response {
                    Ok(MlnrNodeResult::MappedFileToMnode(mnode)) => Ok((*mnode, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn synchronize_log(log_id: usize) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::Synchronize(log_id), *token);
                match &response {
                    Ok(MlnrNodeResult::Synchronized) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }
}

impl Dispatch for MlnrKernelNode {
    type ReadOperation = Access;
    type WriteOperation = Modify;
    type Response = Result<MlnrNodeResult, KError>;

    fn dispatch(&self, op: Self::ReadOperation) -> Self::Response {
        match op {
            Access::FileRead(pid, fd, buffer, len, offset) => {
                let mut userslice = UserSlice::new(buffer, len as usize);
                let process_lookup = self.process_map.read();
                let p = process_lookup
                    .get(&pid)
                    .expect("TODO: FileRead process lookup failed");

                let fd = match p.get_fd(fd as usize) {
                    Some(fd) => fd,
                    None => {
                        return Err(KError::FileSystem {
                            source: FileSystemError::PermissionError,
                        })
                    }
                };
                let mnode_num = fd.get_mnode();
                let flags = fd.get_flags();

                // Check if the file has read-only or read-write permissions before reading it.
                if !flags.is_read() {
                    return Err(KError::FileSystem {
                        source: FileSystemError::PermissionError,
                    });
                }

                // If the arguments doesn't provide an offset,
                // then use the offset associated with the FD.
                let mut curr_offset: usize = offset as usize;
                if offset == -1 {
                    curr_offset = fd.get_offset();
                }

                match self.fs.read(mnode_num, &mut userslice, curr_offset) {
                    Ok(len) => {
                        // Update the FD associated offset only when the
                        // offset wasn't given in the arguments.
                        if offset == -1 {
                            fd.update_offset(curr_offset + len);
                        }
                        Ok(MlnrNodeResult::FileAccessed(len as u64))
                    }
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }

            Access::FileInfo(pid, name, info_ptr) => match self.process_map.read().get(&pid) {
                Some(_) => {
                    let filename;
                    match userptr_to_str(name) {
                        Ok(user_str) => filename = user_str,
                        Err(e) => return Err(e.clone()),
                    }

                    match self.fs.lookup(&filename) {
                        // match on (file_exists, mnode_number)
                        Some(mnode) => {
                            let f_info = self.fs.file_info(*mnode);

                            let mut user_ptr = UserPtr::new(&mut VAddr::from(info_ptr));
                            unsafe {
                                *user_ptr.as_mut_ptr::<FileInfo>() = f_info;
                            }
                            Ok(MlnrNodeResult::FileInfo(0))
                        }
                        None => Err(KError::FileSystem {
                            source: FileSystemError::InvalidFile,
                        }),
                    }
                }
                None => Err(ProcessError::NoProcessFoundForPid.into()),
            },

            Access::FdToMnode(pid, fd) => match self.process_map.read().get(&pid) {
                Some(p) => {
                    let fd = match p.get_fd(fd as usize) {
                        Some(fd) => fd,
                        None => {
                            return Err(KError::FileSystem {
                                source: FileSystemError::PermissionError,
                            })
                        }
                    };
                    let mnode_num = fd.get_mnode();
                    Ok(MlnrNodeResult::MappedFileToMnode(mnode_num))
                }
                None => Err(ProcessError::NoProcessFoundForPid.into()),
            },

            Access::FileNameToMnode(pid, name) => match self.process_map.read().get(&pid) {
                Some(_) => {
                    let filename;
                    match userptr_to_str(name) {
                        Ok(user_str) => filename = user_str,
                        Err(e) => return Err(e.clone()),
                    }

                    match self.fs.lookup(&filename) {
                        // match on (file_exists, mnode_number)
                        Some(mnode) => Ok(MlnrNodeResult::MappedFileToMnode(*mnode)),
                        None => Err(KError::FileSystem {
                            source: FileSystemError::InvalidFile,
                        }),
                    }
                }
                None => Err(ProcessError::NoProcessFoundForPid.into()),
            },

            Access::Synchronize(_log_id) => {
                // A NOP that just makes sure we've advanced the replica
                Ok(MlnrNodeResult::Synchronized)
            }
        }
    }

    fn dispatch_mut(&self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Modify::ProcessAdd(pid) => {
                match self.process_map.write().insert(pid, FileDesc::default()) {
                    Some(_) => Err(KError::ProcessError {
                        source: crate::process::ProcessError::NotEnoughMemory,
                    }),
                    None => Ok(MlnrNodeResult::ProcessAdded(pid)),
                }
            }

            Modify::ProcessRemove(pid) => unimplemented!("Process Remove"),

            Modify::FileOpen(pid, filename, flags, modes) => {
                let flags = FileFlags::from(flags);
                let mnode = self.fs.lookup(&filename);
                if mnode.is_none() && !flags.is_create() {
                    return Err(KError::FileSystem {
                        source: FileSystemError::PermissionError,
                    });
                }
                let mut process_lookup = self.process_map.write();
                let p = process_lookup
                    .get_mut(&pid)
                    .expect("TODO: FileOpen process lookup failed");
                let fd = p.allocate_fd();

                match fd {
                    None => Err(KError::NotSupported),
                    Some(mut fd) => {
                        let mnode_num;
                        if mnode.is_none() {
                            match self.fs.create(&filename, modes) {
                                Ok(m_num) => mnode_num = m_num,
                                Err(e) => {
                                    let fdesc = fd.0 as usize;
                                    process_lookup.get_mut(&pid).unwrap().deallocate_fd(fdesc);
                                    return Err(KError::FileSystem { source: e });
                                }
                            }
                        } else {
                            // File exists and FileOpen is called with O_TRUNC flag.
                            if flags.is_truncate() {
                                self.fs.truncate(&filename);
                            }
                            mnode_num = *mnode.unwrap();
                        }
                        fd.1.update_fd(mnode_num, flags);
                        Ok(MlnrNodeResult::FileOpened(fd.0))
                    }
                }
            }

            Modify::FileWrite(pid, fd, kernslice, len, offset) => {
                let mut process_lookup = self.process_map.read();
                let p = process_lookup
                    .get(&pid)
                    .expect("TODO: FileWrite process lookup failed");
                let fd = match p.get_fd(fd as usize) {
                    Some(fd) => fd,
                    None => {
                        return Err(KError::FileSystem {
                            source: FileSystemError::PermissionError,
                        })
                    }
                };

                let mnode_num = fd.get_mnode();
                let flags = fd.get_flags();

                // Check if the file has write-only or read-write permissions before reading it.
                if !flags.is_write() {
                    return Err(KError::FileSystem {
                        source: FileSystemError::PermissionError,
                    });
                }

                let mut curr_offset: usize = offset as usize;
                if offset == -1 {
                    if flags.is_append() {
                        // If offset value is not provided and file is opened with O_APPEND flag.
                        let finfo = self.fs.file_info(mnode_num);
                        curr_offset = finfo.fsize as usize;
                    } else {
                        // If offset value is not provided and file is doesn't have O_APPEND flag.
                        curr_offset = fd.get_offset();
                    }
                }

                match self.fs.write(mnode_num, &kernslice.clone(), curr_offset) {
                    Ok(len) => {
                        if offset == -1 {
                            // Update offset when FileWrite doesn't give an explicit offset value.
                            fd.update_offset(curr_offset + len);
                        }
                        Ok(MlnrNodeResult::FileAccessed(len as u64))
                    }
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }

            Modify::FileClose(pid, fd) => {
                let mut process_lookup = self.process_map.write();
                let p = process_lookup
                    .get_mut(&pid)
                    .expect("TODO: FileClose process lookup failed");
                let ret = p.deallocate_fd(fd as usize);
                if ret == fd as usize {
                    Ok(MlnrNodeResult::FileClosed(fd))
                } else {
                    Err(KError::FileSystem {
                        source: FileSystemError::InvalidFileDescriptor,
                    })
                }
            }

            Modify::FileDelete(pid, filename) => match self.process_map.read().get(&pid) {
                Some(_) => match self.fs.delete(&filename) {
                    Ok(is_deleted) => Ok(MlnrNodeResult::FileDeleted(is_deleted)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                },
                None => Err(ProcessError::NoProcessFoundForPid.into()),
            },

            Modify::FileRename(pid, oldname, newname) => match self.process_map.read().get(&pid) {
                Some(_) => match self.fs.rename(&oldname, &newname) {
                    Ok(is_renamed) => Ok(MlnrNodeResult::FileRenamed(is_renamed)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                },
                None => Err(ProcessError::NoProcessFoundForPid.into()),
            },

            Modify::MkDir(pid, filename, modes) => match self.process_map.read().get(&pid) {
                Some(_) => match self.fs.mkdir(&filename, modes) {
                    Ok(is_created) => Ok(MlnrNodeResult::DirCreated(is_created)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                },
                None => Err(ProcessError::NoProcessFoundForPid.into()),
            },

            Modify::Invalid => unreachable!("Got invalid OP"),
        }
    }
}
