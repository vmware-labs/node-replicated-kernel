#![allow(unused)]

use crate::prelude::*;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use cstr_core::CStr;
use hashbrown::HashMap;
use kpi::process::{FrameId, ProcessInfo};
use kpi::{io::*, FileOperation};

use node_replication::Dispatch;

use crate::arch::process::{UserPtr, UserSlice};
use crate::arch::Module;
use crate::error::KError;
use crate::fs::{
    Buffer, FileDescriptor, FileSystem, FileSystemError, Filename, Flags, Len, MemFS, Modes,
    Offset, FD, MAX_FILES_PER_PROCESS,
};
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{Eid, Executor, Pid, Process, ProcessError};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    CurrentExecutor(topology::GlobalThreadId),
    ProcessInfo(Pid),
    FileRead(Pid, FD, Buffer, Len, Offset),
    MemResolve(Pid, VAddr),
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
    MemUnmap,
    FileOpen(Pid, Filename, Flags, Modes),
    FileWrite(Pid, FD, Buffer, Len, Offset),
    FileClose(Pid, FD),
    FileInfo(Pid, Filename, u64),
    FileDelete(Pid, Filename),
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
    Unmapped,
    Resolved(PAddr, MapAction),
    FileOpened(FD),
    FileClosed(u64),
    FileAccessed(Len),
    FileInfo(u64),
    FileDeleted(bool),
    Executor(Weak<E>),
    FrameId(usize),
    Invalid,
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
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response =
                    replica.execute_ro(ReadOps::MemResolve(pid, base), kcb.arch.replica_idx);

                match response {
                    Ok(NodeResult::Resolved(paddr, rights)) => Ok((paddr.as_u64(), 0x0)),
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
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response =
                    replica.execute(Op::MemMapDevice(pid, frame, action), kcb.arch.replica_idx);

                match response {
                    Ok(NodeResult::Mapped) => Ok((frame.base.as_u64(), frame.size() as u64)),
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
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response = replica.execute(
                    Op::MemMapFrameId(pid, base, frame_id, action),
                    kcb.arch.replica_idx,
                );
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
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let mut virtual_offset = 0;
                for frame in frames {
                    let response = replica.execute(
                        Op::MemMapFrame(pid, base + virtual_offset, frame, action),
                        kcb.arch.replica_idx,
                    );

                    match response {
                        Ok(NodeResult::Mapped) => {}
                        e => unreachable!("Got unexpected response {:?}", e),
                    };

                    virtual_offset += frame.size();
                }

                Ok((base.as_u64(), virtual_offset as u64))
            })
    }

    pub fn map_fd(pid: Pid, pathname: u64, flags: u64, modes: u64) -> Result<(FD, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response = replica.execute(
                    Op::FileOpen(pid, pathname, flags, modes),
                    kcb.arch.replica_idx,
                );

                match &response {
                    Ok(NodeResult::FileOpened(fd)) => Ok((*fd, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn unmap_fd(pid: Pid, fd: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response = replica.execute(Op::FileClose(pid, fd), kcb.arch.replica_idx);

                match &response {
                    Ok(NodeResult::FileClosed(0)) => Ok((0, 0)),
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
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| match op {
                FileOperation::Read | FileOperation::ReadAt => {
                    let response = replica.execute_ro(
                        ReadOps::FileRead(pid, fd, buffer, len, offset),
                        kcb.arch.replica_idx,
                    );

                    match &response {
                        Ok(NodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }

                FileOperation::Write | FileOperation::WriteAt => {
                    let response = replica.execute(
                        Op::FileWrite(pid, fd, buffer, len, offset),
                        kcb.arch.replica_idx,
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
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response =
                    replica.execute(Op::FileInfo(pid, name, info_ptr), kcb.arch.replica_idx);

                match &response {
                    Ok(NodeResult::FileInfo(f_info)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn file_delete(pid: Pid, name: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response = replica.execute(Op::FileDelete(pid, name), kcb.arch.replica_idx);

                match &response {
                    Ok(NodeResult::FileDeleted(_)) => Ok((0, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }

    pub fn pinfo(pid: Pid) -> Result<ProcessInfo, KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response = replica.execute_ro(ReadOps::ProcessInfo(pid), kcb.arch.replica_idx);

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

        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response = replica.execute(
                    Op::ProcAllocateCore(pid, gtid, affinity, entry_point),
                    kcb.arch.replica_idx,
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

        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let response =
                    replica.execute(Op::AllocateFrameToProcess(pid, frame), kcb.arch.replica_idx);
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
    type Response = NodeResult<P::E>;
    type ResponseError = KError;

    fn dispatch(&self, op: Self::ReadOperation) -> Result<Self::Response, Self::ResponseError> {
        match op {
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

                match self.fs.read(mnode_num, &mut userslice, offset) {
                    Ok(len) => Ok(NodeResult::FileAccessed(len as u64)),
                    Err(e) => Err(KError::FileSystem { source: e }),
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

    fn dispatch_mut(
        &mut self,
        op: Self::WriteOperation,
    ) -> Result<Self::Response, Self::ResponseError> {
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
                let mut pmanager = kcb.mem_manager();

                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");
                p.vspace_mut()
                    .map_frame(base, frame, action, &mut *pmanager)?;
                Ok(NodeResult::Mapped)
            }
            Op::MemMapDevice(pid, frame, action) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let kcb = crate::kcb::get_kcb();
                let mut pmanager = kcb.mem_manager();

                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");

                let base = VAddr::from(frame.base.as_u64());
                p.vspace_mut()
                    .map_frame(base, frame, action, &mut *pmanager)
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
                let mut pmanager = kcb.mem_manager();

                p.vspace_mut()
                    .map_frame(base, frame, action, &mut *pmanager)?;
                Ok(NodeResult::MappedFrameId(frame.base, frame.size))
            }
            Op::MemAdjust => unreachable!(),
            Op::MemUnmap => unreachable!(),
            Op::FileOpen(pid, pathname, flags, modes) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");

                let mut user_ptr = VAddr::from(pathname);
                let str_ptr = UserPtr::new(&mut user_ptr);

                let filename;
                unsafe {
                    match CStr::from_ptr(str_ptr.as_mut_ptr()).to_str() {
                        Ok(path) => {
                            if !path.is_ascii() || path.is_empty() {
                                return Err(KError::NotSupported);
                            }
                            filename = path;
                        }
                        Err(_) => unreachable!("FileOpen: Unable to convert u64 to str"),
                    }
                }

                let flags = FileFlags::from(flags);
                let mnode = self.fs.lookup(filename);
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
                            match self.fs.create(filename, modes) {
                                Ok(m_num) => mnode_num = m_num,
                                Err(e) => {
                                    let fdesc = fd.0 as usize;
                                    p.deallocate_fd(fdesc);
                                    return Err(KError::FileSystem { source: e });
                                }
                            }
                        } else {
                            mnode_num = *mnode.unwrap();
                        }
                        fd.1.update_fd(mnode_num, flags);
                        Ok(NodeResult::FileOpened(fd.0))
                    }
                }
            }
            Op::FileWrite(pid, fd, buffer, len, offset) => {
                let mut userslice = UserSlice::new(buffer, len as usize);
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");
                let fd = p.get_fd(fd as usize);
                let mnode_num = fd.get_mnode();
                let flags = fd.get_flags();

                // Check if the file has write-only or read-write permissions before reading it.
                if !flags.is_write() {
                    return Err(KError::FileSystem {
                        source: FileSystemError::PermissionError,
                    });
                }

                match self.fs.write(mnode_num, &mut userslice, offset) {
                    Ok(len) => Ok(NodeResult::FileAccessed(len as u64)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            Op::FileClose(pid, fd) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");
                let ret = p.deallocate_fd(fd as usize);

                if ret == fd as usize {
                    Ok(NodeResult::FileClosed(fd))
                } else {
                    Err(KError::FileSystem {
                        source: FileSystemError::InvalidFileDescriptor,
                    })
                }
            }
            Op::FileInfo(pid, name, info_ptr) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");

                let mut user_ptr = VAddr::from(name);
                let str_ptr = UserPtr::new(&mut user_ptr);

                let filename;
                unsafe {
                    match CStr::from_ptr(str_ptr.as_mut_ptr()).to_str() {
                        Ok(path) => {
                            if !path.is_ascii() || path.is_empty() {
                                return Err(KError::NotSupported);
                            }
                            filename = path;
                        }
                        Err(_) => unreachable!("FileOpen: Unable to convert u64 to str"),
                    }
                }

                match self.fs.lookup(filename) {
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
            Op::FileDelete(pid, pathname) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let mut p = process_lookup.expect("TODO: FileCreate process lookup failed");

                let mut user_ptr = VAddr::from(pathname);
                let str_ptr = UserPtr::new(&mut user_ptr);

                let filename;
                unsafe {
                    match CStr::from_ptr(str_ptr.as_mut_ptr()).to_str() {
                        Ok(path) => {
                            if !path.is_ascii() || path.is_empty() {
                                return Err(KError::NotSupported);
                            }
                            filename = path;
                        }
                        Err(_) => unreachable!("FileOpen: Unable to convert u64 to str"),
                    }
                }
                match self.fs.delete(filename) {
                    Ok(is_deleted) => Ok(NodeResult::FileDeleted(is_deleted)),
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
