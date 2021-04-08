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
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    CurrentExecutor(atopology::GlobalThreadId),
    ProcessInfo(Pid),
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
        Option<atopology::NodeId>,
        Option<atopology::GlobalThreadId>,
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
    CoreAllocated(atopology::GlobalThreadId, Eid),
    VectorAllocated(u64),
    ExecutorsCreated(usize),
    Mapped,
    MappedFrameId(PAddr, usize),
    Adjusted,
    Unmapped(TlbFlushHandle),
    Resolved(PAddr, MapAction),
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
    scheduler_map: HashMap<atopology::GlobalThreadId, Arc<P::E>>,
}

impl<P: Process> Default for KernelNode<P> {
    fn default() -> KernelNode<P> {
        KernelNode {
            current_pid: 1,
            process_map: HashMap::with_capacity(256),
            scheduler_map: HashMap::with_capacity(256),
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
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<(atopology::GlobalThreadId, Eid), KError> {
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
