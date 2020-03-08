#![allow(unused)]

use crate::prelude::*;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use cstr_core::CStr;
use hashbrown::HashMap;
use kpi::{io::*, FileOperation};
use node_replication::Dispatch;

use crate::arch::process::UserPtr;
use crate::arch::Module;
use crate::error::KError;
use crate::fs::{
    Buffer, FileDescriptor, FileSystem, FileSystemError, Filename, Flags, Len, MemFS, Modes,
    Offset, FD, MAX_FILES_PER_PROCESS,
};
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{Eid, Executor, Pid, Process};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Op {
    ProcCreate(&'static Module),
    ProcDestroy(Pid),
    ProcInstallVCpuArea(Pid, u64),
    ProcAllocIrqVector,
    ProcRaiseIrq,
    DispAlloc(Pid, Frame),
    DispDealloc,
    DispSchedule,
    MemMapFrames(Pid, VAddr, Frame, MapAction), // Vec<Frame> doesn't implement copy
    MemMapFrame(Pid, VAddr, Frame, MapAction),
    MemMapDevice(Pid, Frame, MapAction),
    MemAdjust,
    MemUnmap,
    MemResolve(Pid, VAddr),
    FileOpen(Pid, Filename, Flags, Modes),
    FileRead(Pid, FD, Buffer, Len, Offset),
    FileWrite(Pid, FD, Buffer, Len, Offset),
    FileClose(Pid, FD),
    FileInfo(Pid, Filename),
    FileDelete(Pid, Filename),
    Invalid,
}

impl Default for Op {
    fn default() -> Self {
        Op::Invalid
    }
}

#[derive(Copy, Eq, PartialEq, Debug, Clone)]
pub enum NodeResult<E: Executor> {
    ProcCreated(Pid),
    ProcDestroyed,
    VectorAllocated(u64),
    ReqExecutor(*mut E),
    Mapped,
    Adjusted,
    Unmapped,
    Resolved(PAddr, MapAction),
    FileOpened(FD),
    FileClosed(u64),
    FileAccessed(Len),
    FileInfo(Len, u64),
    FileDeleted(bool),
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
    fs: MemFS,
}

impl<P: Process> Default for KernelNode<P> {
    fn default() -> KernelNode<P> {
        KernelNode {
            current_pid: 1,
            process_map: HashMap::with_capacity(256),
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
                let mut o = vec![];

                replica.execute(Op::MemResolve(pid, base), kcb.arch.replica_idx);
                while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                debug_assert_eq!(o.len(), 1, "Should get reply");

                match o[0] {
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
                let mut o = vec![];

                replica.execute(Op::MemMapDevice(pid, frame, action), kcb.arch.replica_idx);
                while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                debug_assert_eq!(o.len(), 1, "Should get reply");

                match o[0] {
                    Ok(NodeResult::Mapped) => Ok((frame.base.as_u64(), frame.size() as u64)),
                    _ => unreachable!("Got unexpected response"),
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
                let mut o = vec![];

                let mut virtual_offset = 0;
                for frame in frames {
                    replica.execute(
                        Op::MemMapFrame(pid, base + virtual_offset, frame, action),
                        kcb.arch.replica_idx,
                    );
                    while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                    debug_assert_eq!(o.len(), 1, "Should get a reply?");

                    match o[0] {
                        Ok(NodeResult::Mapped) => {}
                        _ => unreachable!("Got unexpected response"),
                    };

                    virtual_offset += frame.size();
                    o.clear();
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
                let mut o = vec![];
                replica.execute(
                    Op::FileOpen(pid, pathname, flags, modes),
                    kcb.arch.replica_idx,
                );

                while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                debug_assert_eq!(o.len(), 1, "Should get a reply?");

                match &o[0] {
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
                let mut o = vec![];
                replica.execute(Op::FileClose(pid, fd), kcb.arch.replica_idx);

                while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                debug_assert_eq!(o.len(), 1, "Should get a reply?");

                match &o[0] {
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
                    let mut o = vec![];
                    replica.execute(
                        Op::FileRead(pid, fd, buffer, len, offset),
                        kcb.arch.replica_idx,
                    );

                    while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                    debug_assert_eq!(o.len(), 1, "Should get a reply?");

                    match &o[0] {
                        Ok(NodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }

                FileOperation::Write | FileOperation::WriteAt => {
                    let mut o = vec![];
                    replica.execute(
                        Op::FileWrite(pid, fd, buffer, len, offset),
                        kcb.arch.replica_idx,
                    );

                    while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                    debug_assert_eq!(o.len(), 1, "Should get a reply?");

                    match &o[0] {
                        Ok(NodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }
                _ => unreachable!(),
            })
    }

    pub fn file_info(pid: Pid, name: u64) -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |replica| {
                let mut o = vec![];
                replica.execute(Op::FileInfo(pid, name), kcb.arch.replica_idx);

                while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                debug_assert_eq!(o.len(), 1, "Should get a reply?");

                match &o[0] {
                    Ok(NodeResult::FileInfo(len, ftype)) => Ok((*len, *ftype)),
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
                let mut o = vec![];
                replica.execute(Op::FileDelete(pid, name), kcb.arch.replica_idx);

                while replica.get_responses(kcb.arch.replica_idx, &mut o) == 0 {}
                debug_assert_eq!(o.len(), 1, "Should get a reply?");

                match &o[0] {
                    Ok(NodeResult::FileDeleted(_)) => Ok((0, 0)),
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
    type ReadOperation = ();
    type WriteOperation = Op;
    type Response = NodeResult<P::E>;
    type ResponseError = KError;

    fn dispatch(&self, op: Self::ReadOperation) -> Result<Self::Response, Self::ResponseError> {
        unimplemented!("dispatch");
    }

    fn dispatch_mut(
        &mut self,
        op: Self::WriteOperation,
    ) -> Result<Self::Response, Self::ResponseError> {
        match op {
            Op::ProcCreate(module) => match P::new(module, self.current_pid) {
                Ok(process) => {
                    //self.process_map.try_reserve(1);
                    let pid = self.current_pid;
                    self.process_map.insert(pid, Box::new(process));
                    self.current_pid += 1;
                    Ok(NodeResult::ProcCreated(pid))
                }
                Err(e) => {
                    error!("Failed to create process {:?}", e);
                    Err(KError::ProcessCreate {
                        desc: e.to_string(),
                    })
                }
            },
            Op::ProcDestroy(pid) => {
                // TODO(correctness): This is just a trivial,
                // wrong implementation at the moment
                let process = self.process_map.remove(&pid);
                if process.is_some() {
                    drop(process);
                    Ok(NodeResult::ProcDestroyed)
                } else {
                    error!("Process not found");
                    Err(KError::NotSupported)
                }
            }
            Op::ProcInstallVCpuArea(_, _) => unreachable!(),
            Op::ProcAllocIrqVector => unreachable!(),
            Op::ProcRaiseIrq => unreachable!(),
            Op::DispAlloc(pid, frame) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let p = process_lookup.expect("TODO: DispAlloc process lookup failed");
                p.allocate_executors(frame)
                    .expect("Can't allocate dispatchers");
                let executor = p
                    .get_executor(0) // TODO (fixnow): Hard-coded 0
                    .expect("Can't get an executor for process");
                //NodeResult::ReqExecutor(executor)
                Ok(NodeResult::ReqExecutor(Box::into_raw(executor)))
            }
            Op::DispDealloc => unreachable!(),
            Op::DispSchedule => unreachable!(),
            Op::MemMapFrames(pid, base, frames, action) => unimplemented!("MemMapFrames"),
            Op::MemMapFrame(pid, base, frame, action) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let kcb = crate::kcb::get_kcb();
                let mut pmanager = kcb.mem_manager();

                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");
                p.vspace()
                    .map_frame(base, frame, action, &mut *pmanager)
                    .expect("TODO: MemMapFrame map_frame failed");
                Ok(NodeResult::Mapped)
            }
            Op::MemMapDevice(pid, frame, action) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let kcb = crate::kcb::get_kcb();
                let mut pmanager = kcb.mem_manager();

                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");

                let base = VAddr::from(frame.base.as_u64());
                p.vspace()
                    .map_frame(base, frame, action, &mut *pmanager)
                    .expect("TODO: MemMapFrame map_frame failed");
                Ok(NodeResult::Mapped)
            }
            Op::MemAdjust => unreachable!(),
            Op::MemUnmap => unreachable!(),
            Op::MemResolve(pid, base) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let kcb = crate::kcb::get_kcb();
                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");

                let (paddr, rights) = p
                    .vspace()
                    .resolve(base)
                    .expect("TODO: MemMapFrame map_frame failed");
                Ok(NodeResult::Resolved(paddr, rights))
            }
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
                let (is_file, mnode) = self.fs.lookup(filename);
                if !is_file && !flags.is_create() {
                    return Err(KError::FileSystem {
                        source: FileSystemError::PermissionError,
                    });
                }

                let fd = p.allocate_fd();
                match fd {
                    None => Err(KError::NotSupported),
                    Some(mut fd) => {
                        let mnode_num;
                        if !is_file {
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
            Op::FileRead(pid, fd, buffer, len, offset) => {
                let process_lookup = self.process_map.get_mut(&pid);
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

                match self.fs.read(mnode_num, buffer, len, offset) {
                    Ok(len) => Ok(NodeResult::FileAccessed(len as u64)),
                    Err(e) => Err(KError::FileSystem { source: e }),
                }
            }
            Op::FileWrite(pid, fd, buffer, len, offset) => {
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

                match self.fs.write(mnode_num, buffer, len, offset) {
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
            Op::FileInfo(pid, name) => {
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
                    (true, Some(mnode)) => {
                        let (size, ftype) = self.fs.file_info(*mnode);
                        Ok(NodeResult::FileInfo(size, ftype))
                    }
                    (false, _) | (true, None) => Err(KError::FileSystem {
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
            Op::Invalid => unreachable!("Got invalid OP"),
        }
    }
}
