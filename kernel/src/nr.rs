// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]

use crate::prelude::*;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use hashbrown::HashMap;
use kpi::process::{FrameId, ProcessInfo};
use kpi::{io::*, FileOperation};

use node_replication::Dispatch;
use node_replication::ReplicaToken;

use crate::arch::process::{UserPtr, UserSlice};
use crate::arch::Module;
use crate::error::KError;
use crate::fs::{
    Buffer, FileDescriptor, FileSystem, FileSystemError, Filename, Flags, Len, MemFS, Modes,
    Offset, FD, MAX_FILES_PER_PROCESS,
};
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    CurrentExecutor(topology::GlobalThreadId),
    ProcessInfo(Pid),
    FileRead(Pid, FD, Buffer, Len, Offset),
    FileInfo(Pid, Filename, u64),
    MemResolve(Pid, VAddr),
    Synchronize,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Op {
    ProcCreate(&'static Module, Vec<Frame>),
    ProcDestroy(Pid),
    ProcInstallVCpuArea(Pid, u64),
    ProcAllocIrqVector,
    ProcRaiseIrq,
    /// Assign a core to a process.
    ProcAllocateCore(
        Pid,
        Option<topology::NodeId>,
        Option<topology::GlobalThreadId>,
        VAddr,
    ),
    /// Assign a physical frame to a process (returns a FrameId).
    AllocateFrameToProcess(Pid, Frame),
    DispatcherAllocation(Pid, Frame),
    DispatcherDeallocation,
    DispatcherSchedule,
    MemMapFrames(Pid, VAddr, Frame, MapAction), // Vec<Frame> doesn't implement copy
    MemMapFrame(Pid, VAddr, Frame, MapAction),
    MemMapDevice(Pid, Frame, MapAction),
    MemMapFrameId(Pid, VAddr, FrameId, MapAction),
    MemAdjust,
    MemUnmap(Pid, VAddr),
    FileOpen(Pid, String, Flags, Modes),
    FileWrite(Pid, FD, Arc<[u8]>, Len, Offset),
    FileClose(Pid, FD),
    FileDelete(Pid, String),
    FileRename(Pid, String, String),
    MkDir(Pid, String, Modes),
    Invalid,
}

impl Default for Op {
    fn default() -> Self {
        Op::Invalid
    }
}

#[derive(Debug, Clone)]
pub enum NodeResult<E: Executor> {
    ProcCreated(Pid),
    ProcDestroyed,
    ProcessInfo(ProcessInfo),
    CoreAllocated(topology::GlobalThreadId, Eid),
    VectorAllocated(u64),
    ExecutorsCreated(usize),
    Mapped,
    MappedFrameId(PAddr, usize),
    Adjusted,
    Unmapped(TlbFlushHandle),
    Resolved(PAddr, MapAction),
    FileOpened(FD),
    FileClosed(u64),
    FileAccessed(Len),
    FileInfo(u64),
    FileDeleted(bool),
    FileRenamed(bool),
    DirCreated(bool),
    Executor(Weak<E>),
    FrameId(usize),
    Invalid,
    Synchronized,
}

impl<E: Executor> Default for NodeResult<E> {
    fn default() -> Self {
        NodeResult::Invalid
    }
}

pub struct KernelNode<P: Process> {
    current_pid: Pid,
    process_map: HashMap<Pid, Box<P>>,
    scheduler_map: HashMap<topology::GlobalThreadId, Arc<P::E>>,
    fs: MemFS,
}

impl<P: Process> Default for KernelNode<P> {
    fn default() -> KernelNode<P> {
        KernelNode {
            current_pid: 1,
            process_map: HashMap::with_capacity(256),
            scheduler_map: HashMap::with_capacity(256),
            fs: Default::default(),
        }
    }
}

// TODO(api-ergonomics): Fix ugly execute API
impl<P: Process> KernelNode<P> {
    pub fn resolve(pid: Pid, base: VAddr) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(ReadOps::MemResolve(pid, base), *token);

                match response {
                    Ok(NodeResult::Resolved(paddr, rights)) => Ok((paddr.as_u64(), 0x0)),
                    Err(e) => Err(e.clone()),
                    _ => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn synchronize() -> Result<(), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(ReadOps::Synchronize, *token);

                match response {
                    Ok(NodeResult::Synchronized) => Ok(()),
                    _ => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn map_device_frame(
        pid: Pid,
        frame: Frame,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Op::MemMapDevice(pid, frame, action), *token);

                match response {
                    Ok(NodeResult::Mapped) => Ok((frame.base.as_u64(), frame.size() as u64)),
                    _ => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn unmap(pid: Pid, base: VAddr) -> Result<TlbFlushHandle, KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Op::MemUnmap(pid, base), *token);

                match response {
                    Ok(NodeResult::Unmapped(handle)) => Ok(handle),
                    _ => unreachable!("Got unexpected response"),
                }
            })
    }

    pub fn map_frame_id(
        pid: Pid,
        frame_id: FrameId,
        base: VAddr,
        action: MapAction,
    ) -> Result<(PAddr, usize), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response =
                    replica.execute_mut(Op::MemMapFrameId(pid, base, frame_id, action), *token);
                match response {
                    Ok(NodeResult::MappedFrameId(paddr, size)) => Ok((paddr, size)),
                    Err(e) => unreachable!("MappedFrameId {:?}", e),
                    _ => unreachable!("unexpected response"),
                }
            })
    }

    pub fn map_frames(
        pid: Pid,
        base: VAddr,
        frames: Vec<Frame>,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let mut virtual_offset = 0;
                for frame in frames {
                    let response = replica.execute_mut(
                        Op::MemMapFrame(pid, base + virtual_offset, frame, action),
                        *token,
                    );

                    match response {
                        Ok(NodeResult::Mapped) => {}
                        e => unreachable!(
                            "Got unexpected response MemMapFrame {:?} {:?} {:?} {:?}",
                            e,
                            base + virtual_offset,
                            frame,
                            action
                        ),
                    };

                    virtual_offset += frame.size();
                }

                Ok((base.as_u64(), virtual_offset as u64))
            })
    }

    pub fn map_fd(pid: Pid, pathname: u64, flags: u64, modes: u64) -> Result<(FD, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename;
                match userptr_to_str(pathname) {
                    Ok(user_str) => filename = user_str,
                    Err(e) => return Err(e.clone()),
                }

                let response =
                    replica.execute_mut(Op::FileOpen(pid, filename, flags, modes), *token);

                match &response {
                    Ok(NodeResult::FileOpened(fd)) => Ok((*fd, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn unmap_fd(pid: Pid, fd: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Op::FileClose(pid, fd), *token);

                match &response {
                    Ok(NodeResult::FileClosed(_)) => Ok((0, 0)),
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
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| match op {
                FileOperation::Read | FileOperation::ReadAt => {
                    let response =
                        replica.execute(ReadOps::FileRead(pid, fd, buffer, len, offset), *token);

                    match &response {
                        Ok(NodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }

                FileOperation::Write | FileOperation::WriteAt => {
                    let kernslice = KernSlice::new(buffer, len as usize);

                    let response = replica.execute_mut(
                        Op::FileWrite(pid, fd, kernslice.buffer.clone(), len, offset),
                        *token,
                    );

                    match &response {
                        Ok(NodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }
                _ => unreachable!(),
            })
    }

    pub fn file_info(pid: Pid, name: u64, info_ptr: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(ReadOps::FileInfo(pid, name, info_ptr), *token);

                match &response {
                    Ok(NodeResult::FileInfo(f_info)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_delete(pid: Pid, name: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename;
                match userptr_to_str(name) {
                    Ok(user_str) => filename = user_str,
                    Err(e) => return Err(e.clone()),
                }
                let response = replica.execute_mut(Op::FileDelete(pid, filename), *token);

                match &response {
                    Ok(NodeResult::FileDeleted(_)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_rename(pid: Pid, oldname: u64, newname: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
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
                    replica.execute_mut(Op::FileRename(pid, oldfilename, newfilename), *token);
                match &response {
                    Ok(NodeResult::FileRenamed(_)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn mkdir(pid: Pid, pathname: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let filename;
                match userptr_to_str(pathname) {
                    Ok(user_str) => filename = user_str,
                    Err(e) => return Err(e.clone()),
                }

                let response = replica.execute_mut(Op::MkDir(pid, filename, modes), *token);

                match &response {
                    Ok(NodeResult::DirCreated(true)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn pinfo(pid: Pid) -> Result<ProcessInfo, KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(ReadOps::ProcessInfo(pid), *token);

                match &response {
                    Ok(NodeResult::ProcessInfo(pinfo)) => Ok(*pinfo),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<topology::NodeId>,
        gtid: Option<topology::GlobalThreadId>,
    ) -> Result<(topology::GlobalThreadId, Eid), KError> {
        let kcb = super::kcb::get_kcb();

        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(
                    Op::ProcAllocateCore(pid, gtid, affinity, entry_point),
                    *token,
                );

                match &response {
                    Ok(NodeResult::CoreAllocated(rgtid, eid)) => {
                        let _r = gtid.map(|gtid| debug_assert_eq!(gtid, *rgtid));
                        Ok((*rgtid, *eid))
                    }
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn allocate_frame_to_process(pid: Pid, frame: Frame) -> Result<FrameId, KError> {
        let kcb = super::kcb::get_kcb();

        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Op::AllocateFrameToProcess(pid, frame), *token);
                match response {
                    Ok(NodeResult::FrameId(fid)) => Ok(fid),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }
}

impl<P> Dispatch for KernelNode<P>
where
    P: Process,
    P::E: Copy,
{
    type ReadOperation = ReadOps;
    type WriteOperation = Op;
    type Response = Result<NodeResult<P::E>, KError>;

    fn dispatch(&self, op: Self::ReadOperation) -> Self::Response {
        match op {
            ReadOps::Synchronize => {
                // A NOP that just makes sure we've advanced the replica
                Ok(NodeResult::Synchronized)
            }
            ReadOps::FileRead(pid, fd, buffer, len, offset) => {
                let mut userslice = UserSlice::new(buffer, len as usize);
                let process_lookup = self.process_map.get(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");
                let fd = p.get_fd(fd as usize);
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
                        Ok(NodeResult::FileAccessed(len as u64))
                    }
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            ReadOps::FileInfo(pid, name, info_ptr) => {
                let process_lookup = self.process_map.get(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");

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
                        Ok(NodeResult::FileInfo(0))
                    }
                    None => Err(KError::FileSystem {
                        source: FileSystemError::InvalidFile,
                    }),
                }
            }
            ReadOps::ProcessInfo(pid) => {
                let process_lookup = self.process_map.get(&pid);
                let p = process_lookup.expect("TODO: process lookup failed");
                Ok(NodeResult::ProcessInfo(*p.pinfo()))
            }
            ReadOps::CurrentExecutor(gtid) => {
                let executor = self
                    .scheduler_map
                    .get(&gtid)
                    .ok_or(KError::NoExecutorForCore)?;
                Ok(NodeResult::Executor(Arc::downgrade(executor)))
            }
            ReadOps::MemResolve(pid, base) => {
                let process_lookup = self.process_map.get(&pid);
                let kcb = crate::kcb::get_kcb();
                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");

                let (paddr, rights) = p.vspace().resolve(base)?;
                Ok(NodeResult::Resolved(paddr, rights))
            }
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Op::ProcCreate(module, writeable_sections) => {
                P::new(module, self.current_pid, writeable_sections)
                    .and_then(|process| {
                        //self.process_map.try_reserve(1);
                        let pid = self.current_pid;
                        self.process_map.insert(pid, Box::new(process));
                        self.current_pid += 1;
                        Ok(NodeResult::ProcCreated(pid))
                    })
                    .map_err(|e| e.into())
            }
            Op::ProcDestroy(pid) => {
                // TODO(correctness): This is just a trivial,
                // wrong implementation at the moment
                let process = self.process_map.remove(&pid);
                if process.is_some() {
                    drop(process);
                    Ok(NodeResult::ProcDestroyed)
                } else {
                    error!("Process not found");
                    Err(ProcessError::NoProcessFoundForPid.into())
                }
            }
            Op::ProcInstallVCpuArea(_, _) => unreachable!(),
            Op::ProcAllocIrqVector => unreachable!(),
            Op::ProcRaiseIrq => unreachable!(),
            Op::DispatcherAllocation(pid, frame) => {
                let p = self
                    .process_map
                    .get_mut(&pid)
                    .ok_or(ProcessError::NoProcessFoundForPid)?;
                let how_many = p.allocate_executors(frame)?;
                Ok(NodeResult::ExecutorsCreated(how_many))
            }
            Op::DispatcherDeallocation => unreachable!(),
            Op::DispatcherSchedule => unreachable!(),
            Op::MemMapFrames(pid, base, frames, action) => unimplemented!("MemMapFrames"),
            Op::MemMapFrame(pid, base, frame, action) => {
                let process_lookup = self.process_map.get_mut(&pid);
                crate::memory::KernelAllocator::try_refill_tcache(7, 0)?;

                let kcb = crate::kcb::get_kcb();
                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");
                p.vspace_mut().map_frame(base, frame, action)?;
                Ok(NodeResult::Mapped)
            }
            Op::MemMapDevice(pid, frame, action) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let kcb = crate::kcb::get_kcb();
                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");

                let base = VAddr::from(frame.base.as_u64());
                p.vspace_mut()
                    .map_frame(base, frame, action)
                    .expect("TODO: MemMapFrame map_frame failed");
                Ok(NodeResult::Mapped)
            }
            Op::MemMapFrameId(pid, base, frame_id, action) => {
                let p = self
                    .process_map
                    .get_mut(&pid)
                    .ok_or(ProcessError::NoProcessFoundForPid)?;
                let frame = p.get_frame(frame_id)?;

                crate::memory::KernelAllocator::try_refill_tcache(7, 0)?;

                let kcb = crate::kcb::get_kcb();
                p.vspace_mut().map_frame(base, frame, action)?;
                Ok(NodeResult::MappedFrameId(frame.base, frame.size))
            }
            Op::MemAdjust => unreachable!(),
            Op::MemUnmap(pid, vaddr) => {
                let p = self
                    .process_map
                    .get_mut(&pid)
                    .ok_or(ProcessError::NoProcessFoundForPid)?;

                let kcb = crate::kcb::get_kcb();
                let mut shootdown_handle = p.vspace_mut().unmap(vaddr)?;
                // Figure out which cores are running our current process
                // (this is where we send IPIs later)
                for (gtid, e) in self.scheduler_map.iter() {
                    if pid == e.pid() {
                        shootdown_handle.add_core(*gtid);
                    }
                }

                Ok(NodeResult::Unmapped(shootdown_handle))
            }
            Op::FileOpen(pid, filename, flags, modes) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileOpen process lookup failed");

                let flags = FileFlags::from(flags);
                let mnode = self.fs.lookup(&filename);
                if mnode.is_none() && !flags.is_create() {
                    return Err(KError::FileSystem {
                        source: FileSystemError::PermissionError,
                    });
                }

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
                                    p.deallocate_fd(fdesc);
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
                        Ok(NodeResult::FileOpened(fd.0))
                    }
                }
            }
            Op::FileWrite(pid, fd, kernslice, len, offset) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileWrite process lookup failed");
                let fd = p.get_fd(fd as usize);
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
                        Ok(NodeResult::FileAccessed(len as u64))
                    }
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            Op::FileClose(pid, fd) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileClose process lookup failed");
                let ret = p.deallocate_fd(fd as usize);

                if ret == fd as usize {
                    Ok(NodeResult::FileClosed(fd))
                } else {
                    Err(KError::FileSystem {
                        source: FileSystemError::InvalidFileDescriptor,
                    })
                }
            }
            Op::FileDelete(pid, filename) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileDelete process lookup failed");
                match self.fs.delete(&filename) {
                    Ok(is_deleted) => Ok(NodeResult::FileDeleted(is_deleted)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            Op::FileRename(pid, oldname, newname) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileRename process lookup failed");
                match self.fs.rename(&oldname, &newname) {
                    Ok(is_renamed) => Ok(NodeResult::FileRenamed(is_renamed)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            Op::MkDir(pid, filename, modes) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: MkDir process lookup failed");
                match self.fs.mkdir(&filename, modes) {
                    Ok(is_created) => Ok(NodeResult::DirCreated(is_created)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            Op::ProcAllocateCore(pid, Some(gtid), Some(region), entry_point) => {
                match self.scheduler_map.get(&gtid) {
                    Some(executor) => {
                        error!("Core {} already used by {}", gtid, executor.id());
                        Err(KError::CoreAlreadyAllocated)
                    }
                    None => {
                        let process = self
                            .process_map
                            .get_mut(&pid)
                            .ok_or(ProcessError::NoProcessFoundForPid)?;
                        let mut executor = process.get_executor(region)?;
                        let eid = executor.id();
                        unsafe {
                            (*executor.vcpu_kernel()).resume_with_upcall = entry_point;
                        }
                        self.scheduler_map.insert(gtid, executor.into());
                        Ok(NodeResult::CoreAllocated(gtid, eid))
                    }
                }
            }
            Op::ProcAllocateCore(pid, a, b, entry_point) => unimplemented!(),
            Op::AllocateFrameToProcess(pid, frame) => {
                let process = self
                    .process_map
                    .get_mut(&pid)
                    .ok_or(ProcessError::NoProcessFoundForPid)?;
                let fid = process.add_frame(frame)?;

                Ok(NodeResult::FrameId(fid))
            }
            Op::Invalid => unreachable!("Got invalid OP"),
        }
    }
}
