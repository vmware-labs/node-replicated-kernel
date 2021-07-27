// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::arch::process::{UserPtr, UserSlice};
use crate::error::KError;
use crate::fs::fd::FileDesc;
use crate::fs::{
    Buffer, FileDescriptor, FileSystem, Filename, Flags, Len, MlnrFS, Mnode, Modes, NrLock, Offset,
    FD, MNODE_OFFSET,
};
use crate::memory::VAddr;
use crate::prelude::*;
use crate::process::{userptr_to_str, KernSlice, Pid};

use alloc::sync::Arc;
use cnr::{Dispatch, LogMapper};
use hashbrown::HashMap;
use kpi::io::*;
use kpi::FileOperation;

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
    FileWrite(Pid, FD, Mnode, Arc<[u8]>, Len, Offset),
    FileClose(Pid, FD),
    FileDelete(Pid, String),
    FileRename(Pid, String, String),
    MkDir(Pid, String, Modes),
}

// TODO: Stateless op to log mapping. Maintain some state for correct redirection.
impl LogMapper for Modify {
    fn hash(&self, nlogs: usize, logs: &mut Vec<usize>) {
        debug_assert!(logs.capacity() >= nlogs, "Push can't fail.");
        logs.clear();
        match self {
            Modify::ProcessAdd(_pid) => push_to_all(nlogs, logs),
            Modify::ProcessRemove(_pid) => push_to_all(nlogs, logs),
            Modify::FileOpen(_pid, _filename, _flags, _modes) => push_to_all(nlogs, logs),
            Modify::FileWrite(_pid, _fd, mnode, _kernslice, _len, _offset) => {
                logs.push((*mnode as usize - MNODE_OFFSET) % nlogs)
            }
            Modify::FileClose(_pid, _fd) => push_to_all(nlogs, logs),
            Modify::FileDelete(_pid, _filename) => push_to_all(nlogs, logs),
            Modify::FileRename(_pid, _oldname, _newname) => push_to_all(nlogs, logs),
            Modify::MkDir(_pid, _name, _modes) => push_to_all(nlogs, logs),
        }

        fn push_to_all(nlogs: usize, logs: &mut Vec<usize>) {
            for i in 0..nlogs {
                logs.push(i);
            }
        }
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Access {
    FileRead(Pid, FD, Mnode, Buffer, Len, Offset),
    FileInfo(Pid, Filename, Mnode, u64),
    FdToMnode(Pid, FD),
    FileNameToMnode(Pid, Filename),
    Synchronize(usize),
}

//TODO: Stateless op to log mapping. Maintain some state for correct redirection.
impl LogMapper for Access {
    fn hash(&self, nlogs: usize, logs: &mut Vec<usize>) {
        debug_assert!(logs.capacity() >= nlogs, "Push can't fail.");
        logs.clear();
        match self {
            Access::FileRead(_pid, _fd, mnode, _buffer, _len, _offser) => {
                logs.push((*mnode as usize - MNODE_OFFSET) % nlogs)
            }
            Access::FileInfo(_pid, _filename, mnode, _info_ptr) => {
                logs.push((*mnode as usize - MNODE_OFFSET) % nlogs)
            }
            // TODO: Assume that all metadata modifying operations go through log 0.
            Access::FdToMnode(_pid, _fd) => logs.push(0),
            Access::FileNameToMnode(_pid, _filename) => logs.push(0),
            // Log number start with 1 in CNR, however, replica uses mod
            // operation which starts with 0; hence `log_id - 1`.
            Access::Synchronize(log_id) => logs.push((*log_id - 1) % nlogs),
        }
    }
}

#[derive(Clone, Debug)]
pub enum MlnrNodeResult {
    ProcessAdded(Pid),
    ProcessRemoved(Pid),
    FileOpened(FD),
    FileAccessed(Len),
    FileClosed(u64),
    FileDeleted,
    FileInfo(FileInfo),
    FileRenamed,
    DirCreated,
    MappedFileToMnode(u64),
    Synchronized,
}

/// TODO: Most of the functions looks same as in nr.rs. Merge the
/// two and maybe move all the functions to a separate file?
impl MlnrKernelNode {
    pub fn add_process(pid: usize) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut_scan(Modify::ProcessAdd(pid), *token);
                match response {
                    Ok(MlnrNodeResult::ProcessAdded(pid)) => Ok((pid as u64, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn map_fd(pid: Pid, pathname: u64, flags: u64, modes: u64) -> Result<(FD, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename = userptr_to_str(pathname)?;
                let response =
                    replica.execute_mut_scan(Modify::FileOpen(pid, filename, flags, modes), *token);

                match response {
                    Ok(MlnrNodeResult::FileOpened(fd)) => Ok((fd, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
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
        let mnode = match MlnrKernelNode::fd_to_mnode(pid, fd) {
            Ok((mnode, _)) => mnode,
            Err(_) => return Err(KError::InvalidFileDescriptor),
        };
        let kcb = super::kcb::get_kcb();
        kcb.arch.cnr_replica.as_ref().map_or(
            Err(KError::ReplicaNotSet),
            |(replica, token)| match op {
                FileOperation::Write | FileOperation::WriteAt => {
                    let kernslice = KernSlice::new(buffer, len as usize);

                    let response = replica.execute_mut(
                        Modify::FileWrite(pid, fd, mnode, kernslice.buffer, len, offset),
                        *token,
                    );

                    match response {
                        Ok(MlnrNodeResult::FileAccessed(len)) => Ok((len, 0)),
                        Err(e) => Err(e),
                        Ok(_) => unreachable!("Got unexpected response"),
                    }
                }

                FileOperation::Read | FileOperation::ReadAt => {
                    let response = replica.execute(
                        Access::FileRead(pid, fd, mnode, buffer, len, offset),
                        *token,
                    );

                    match response {
                        Ok(MlnrNodeResult::FileAccessed(len)) => Ok((len, 0)),
                        Err(e) => Err(e),
                        Ok(_) => unreachable!("Got unexpected response"),
                    }
                }
                _ => unreachable!(),
            },
        )
    }

    pub fn unmap_fd(pid: Pid, fd: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut_scan(Modify::FileClose(pid, fd), *token);

                match response {
                    Ok(MlnrNodeResult::FileClosed(_fd)) => Ok((0, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn file_delete(pid: Pid, name: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename = userptr_to_str(name)?;
                let response = replica.execute_mut_scan(Modify::FileDelete(pid, filename), *token);

                match response {
                    Ok(MlnrNodeResult::FileDeleted) => Ok((0, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn file_info(pid: Pid, name: u64, info_ptr: u64) -> Result<(u64, u64), KError> {
        let (mnode, _) = MlnrKernelNode::filename_to_mnode(pid, name)?;

        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response =
                    replica.execute(Access::FileInfo(pid, name, mnode, info_ptr), *token);

                match response {
                    Ok(MlnrNodeResult::FileInfo(f_info)) => {
                        let user_ptr = UserPtr::new(&mut VAddr::from(info_ptr));
                        unsafe {
                            (*user_ptr.as_mut_ptr::<FileInfo>()).ftype = f_info.ftype;
                            (*user_ptr.as_mut_ptr::<FileInfo>()).fsize = f_info.fsize;
                        }
                        Ok((0, 0))
                    }
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn file_rename(pid: Pid, oldname: u64, newname: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let oldfilename = userptr_to_str(oldname)?;
                let newfilename = userptr_to_str(newname)?;

                let response = replica
                    .execute_mut_scan(Modify::FileRename(pid, oldfilename, newfilename), *token);
                match response {
                    Ok(MlnrNodeResult::FileRenamed) => Ok((0, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn mkdir(pid: Pid, pathname: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename = userptr_to_str(pathname)?;
                let response =
                    replica.execute_mut_scan(Modify::MkDir(pid, filename, modes), *token);

                match response {
                    Ok(MlnrNodeResult::DirCreated) => Ok((0, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    #[inline(always)]
    pub fn fd_to_mnode(pid: Pid, fd: FD) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::FdToMnode(pid, fd), *token);

                match response {
                    Ok(MlnrNodeResult::MappedFileToMnode(mnode)) => Ok((mnode, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    #[inline(always)]
    pub fn filename_to_mnode(pid: Pid, filename: Filename) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::FileNameToMnode(pid, filename), *token);

                match response {
                    Ok(MlnrNodeResult::MappedFileToMnode(mnode)) => Ok((mnode, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn synchronize_log(log_id: usize) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .cnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(Access::Synchronize(log_id), *token);
                match response {
                    Ok(MlnrNodeResult::Synchronized) => Ok((0, 0)),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
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
            Access::FileRead(pid, fd, _mnode, buffer, len, offset) => {
                let mut userslice = UserSlice::new(buffer, len as usize);
                let process_lookup = self.process_map.read();
                let p = process_lookup
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;

                let fd = p.get_fd(fd as usize).ok_or(KError::PermissionError)?;

                let mnode_num = fd.get_mnode();
                let flags = fd.get_flags();

                // Check if the file has read-only or read-write permissions before reading it.
                if !flags.is_read() {
                    return Err(KError::PermissionError);
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
                    Err(e) => Err(e),
                }
            }

            Access::FileInfo(pid, name, _mnode, _info_ptr) => {
                let _p = self
                    .process_map
                    .read()
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;

                let filename = userptr_to_str(name)?;
                let mnode = self.fs.lookup(&filename).ok_or(KError::InvalidFile)?;

                let f_info = self.fs.file_info(*mnode);
                Ok(MlnrNodeResult::FileInfo(f_info))
            }

            Access::FdToMnode(pid, fd) => {
                let process_map_locked = self.process_map.read();
                let p = process_map_locked
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;

                let fd = p.get_fd(fd as usize).ok_or(KError::PermissionError)?;
                let mnode_num = fd.get_mnode();
                Ok(MlnrNodeResult::MappedFileToMnode(mnode_num))
            }

            Access::FileNameToMnode(pid, name) => {
                let _p = self
                    .process_map
                    .read()
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;

                let filename = userptr_to_str(name)?;

                match self.fs.lookup(&filename) {
                    // match on (file_exists, mnode_number)
                    Some(mnode) => Ok(MlnrNodeResult::MappedFileToMnode(*mnode)),
                    None => Err(KError::InvalidFile),
                }
            }

            Access::Synchronize(_log_id) => {
                // A NOP that just makes sure we've advanced the replica
                Ok(MlnrNodeResult::Synchronized)
            }
        }
    }

    fn dispatch_mut(&self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Modify::ProcessAdd(pid) => {
                let mut pmap = self.process_map.write();
                pmap.try_reserve(1)?;
                pmap.try_insert(pid, FileDesc::default())
                    .map_err(|_e| KError::FileDescForPidAlreadyAdded)?;
                Ok(MlnrNodeResult::ProcessAdded(pid))
            }

            Modify::ProcessRemove(pid) => {
                let mut pmap = self.process_map.write();
                let _file_desc = pmap.remove(&pid).ok_or(KError::NoFileDescForPid)?;
                Ok(MlnrNodeResult::ProcessRemoved(pid))
            }

            Modify::FileOpen(pid, filename, flags, modes) => {
                let flags = FileFlags::from(flags);
                let mnode = self.fs.lookup(&filename);
                if mnode.is_none() && !flags.is_create() {
                    return Err(KError::PermissionError);
                }

                let mut pmap = self.process_map.write();
                let p = pmap
                    .get_mut(&pid)
                    .expect("TODO: FileOpen process lookup failed");
                let (fid, fd) = p.allocate_fd().ok_or(KError::NotSupported)?;

                let mnode_num;
                if let Some(mnode) = mnode {
                    // File exists and FileOpen is called with O_TRUNC flag.
                    if flags.is_truncate() {
                        // Truncate may fail if file modes is not readable
                        self.fs.truncate(&filename)?;
                    }
                    mnode_num = *mnode;
                } else {
                    match self.fs.create(&filename, modes) {
                        Ok(m_num) => mnode_num = m_num,
                        Err(e) => {
                            let fdesc = fid as usize;
                            pmap.get_mut(&pid).unwrap().deallocate_fd(fdesc)?;
                            return Err(e);
                        }
                    }
                }

                fd.update_fd(mnode_num, flags);
                Ok(MlnrNodeResult::FileOpened(fid))
            }

            Modify::FileWrite(pid, fd, _mnode, kernslice, _len, offset) => {
                let process_lookup = self.process_map.read();
                let p = process_lookup
                    .get(&pid)
                    .expect("TODO: FileWrite process lookup failed");
                let fd = p.get_fd(fd as usize).ok_or(KError::PermissionError)?;

                let mnode_num = fd.get_mnode();
                let flags = fd.get_flags();

                // Check if the file has write-only or read-write permissions before reading it.
                if !flags.is_write() {
                    return Err(KError::PermissionError);
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

                match self.fs.write(mnode_num, &kernslice, curr_offset) {
                    Ok(len) => {
                        if offset == -1 {
                            // Update offset when FileWrite doesn't give an explicit offset value.
                            fd.update_offset(curr_offset + len);
                        }
                        Ok(MlnrNodeResult::FileAccessed(len as u64))
                    }
                    Err(e) => Err(e),
                }
            }

            Modify::FileClose(pid, fd) => {
                let mut process_lookup = self.process_map.write();
                let p = process_lookup
                    .get_mut(&pid)
                    .expect("TODO: FileClose process lookup failed");
                p.deallocate_fd(fd as usize)?;
                Ok(MlnrNodeResult::FileClosed(fd))
            }

            Modify::FileDelete(pid, filename) => {
                let _p = self
                    .process_map
                    .read()
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;
                let _is_deleted = self.fs.delete(&filename)?;
                Ok(MlnrNodeResult::FileDeleted)
            }

            Modify::FileRename(pid, oldname, newname) => {
                let _p = self
                    .process_map
                    .read()
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;
                let _is_renamed = self.fs.rename(&oldname, &newname)?;
                Ok(MlnrNodeResult::FileRenamed)
            }

            Modify::MkDir(pid, filename, modes) => {
                let _p = self
                    .process_map
                    .read()
                    .get(&pid)
                    .ok_or(KError::NoProcessFoundForPid)?;
                let _is_created = self.fs.mkdir(&filename, modes)?;
                Ok(MlnrNodeResult::DirCreated)
            }
        }
    }
}
