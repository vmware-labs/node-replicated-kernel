// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]

use crate::prelude::*;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use hashbrown::HashMap;
use kpi::io::*;
use kpi::process::{FrameId, ProcessInfo};
use kpi::FileOperation;

use node_replication::{Dispatch, ReplicaToken, Replica, Log};
use lazy_static::lazy_static;

use crate::arch::process::{UserPtr, UserSlice};
use crate::arch::Module;
use crate::error::KError;
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};
use crate::arch::process::Ring3Process;

lazy_static! {
    static ref PROCESS_TABLE: Vec<Arc<Replica<'static, NrProcess<Ring3Process>>>> = {
        let log = Arc::new(Log::<<NrProcess<Ring3Process> as Dispatch>::WriteOperation>::new(
            2 * 1024 * 1024,
        ));

        let mut channels = Vec::with_capacity(12);
        for _i in 0..1 {
            channels.push(Replica::<NrProcess<Ring3Process>>::new(&log));
        }

        channels
    };
}

/*
// The operation log for storing `WriteOperation`, it has a size of 2 MiB:
let log = Arc::new(Log::<<NrProcess as Dispatch>::WriteOperation>::new(
    2 * 1024 * 1024,
));

// Next, we create two replicas of the stack
let replica1 = Replica::<Stack>::new(&log);
let replica2 = Replica::<Stack>::new(&log);
*/


#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    ProcessInfo,
    MemResolve(VAddr),
    Synchronize,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Op {
    ProcRaiseIrq,

    /// Assign a core to a process.
    ProcAllocateCore(
        Pid,
        Option<atopology::NodeId>,
        Option<atopology::GlobalThreadId>,
        VAddr,
    ),

    Destroy,

    /// Assign a physical frame to a process (returns a FrameId).
    AllocateFrameToProcess(Frame),

    DispatcherAllocation(Frame),

    MemMapFrame(VAddr, Frame, MapAction),
    MemMapDevice(Frame, MapAction),
    MemMapFrameId(VAddr, FrameId, MapAction),
    MemAdjust,
    MemUnmap(VAddr),
}

#[derive(Debug, Clone)]
pub enum NodeResult<E: Executor> {
    Destroyed,
    ProcessInfo(ProcessInfo),
    CoreAllocated(atopology::GlobalThreadId, Box<E>),
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

pub struct NrProcess<P: Process> {
    pid: Pid,
    active_cores: Vec<atopology::GlobalThreadId>,
    process: Box<P>,
}

impl<P: Process + Default> Default for NrProcess<P> {
    fn default() -> NrProcess<P> {
        NrProcess {
            pid: 0,
            active_cores: Vec::new(),
            process: Box::new(P::default()),
        }
    }
}

// TODO(api-ergonomics): Fix ugly execute API
impl<P: Process> NrProcess<P> {
    pub fn resolve(pid: Pid, base: VAddr) -> Result<(u64, u64), KError> {
        /*let kcb = super::kcb::get_kcb();
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
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn synchronize() -> Result<(), KError> {
        /*let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute(ReadOps::Synchronize, *token);

                match response {
                    Ok(NodeResult::Synchronized) => Ok(()),
                    _ => unreachable!("Got unexpected response"),
                }
            })
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn map_device_frame(
        pid: Pid,
        frame: Frame,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {

        /*let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Op::MemMapDevice(pid, frame, action), *token);

                match response {
                    Ok(NodeResult::Mapped) => Ok((frame.base.as_u64(), frame.size() as u64)),
                    _ => unreachable!("Got unexpected response"),
                }
            })
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn unmap(pid: Pid, base: VAddr) -> Result<TlbFlushHandle, KError> {
        /*
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
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn map_frame_id(
        pid: Pid,
        frame_id: FrameId,
        base: VAddr,
        action: MapAction,
    ) -> Result<(PAddr, usize), KError> {

        /*let kcb = super::kcb::get_kcb();
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
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn map_frames(
        pid: Pid,
        base: VAddr,
        frames: Vec<Frame>,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {

        /*let kcb = super::kcb::get_kcb();
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
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn pinfo(pid: Pid) -> Result<ProcessInfo, KError> {
        /*
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
        */
        Err(KError::ReplicaNotSet)
    }

    pub fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<(atopology::GlobalThreadId, Eid), KError> {

        /*
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
         */
         Err(KError::ReplicaNotSet)
    }

    pub fn allocate_frame_to_process(pid: Pid, frame: Frame) -> Result<FrameId, KError> {
        /*
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
        */
        Err(KError::ReplicaNotSet)
    }
}

impl<P> Dispatch for NrProcess<P>
where
    P: Process,
    P::E: Copy,
{
    type WriteOperation = Op;
    type ReadOperation = ReadOps;
    type Response = Result<NodeResult<P::E>, KError>;

    fn dispatch(&self, op: Self::ReadOperation) -> Self::Response {
        match op {
            ReadOps::Synchronize => {
                // A NOP that just makes sure we've advanced the replica
                Ok(NodeResult::Synchronized)
            }
            ReadOps::ProcessInfo => {
                Ok(NodeResult::ProcessInfo(*self.process.pinfo()))
            }
            ReadOps::MemResolve(base) => {
                let (paddr, rights) = self.process.vspace().resolve(base)?;
                Ok(NodeResult::Resolved(paddr, rights))
            }
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Op::Destroy => unimplemented!("Destrroy"),
            Op::ProcRaiseIrq => unimplemented!("ProcRaiseIrq"),
            Op::MemAdjust => unimplemented!("MemAdjust"),
            Op::ProcAllocateCore(pid, a, b, entry_point) => unimplemented!("ProcAllocateCore"),

            Op::DispatcherAllocation(frame) => {
                let how_many = self.process.allocate_executors(frame)?;
                Ok(NodeResult::ExecutorsCreated(how_many))
            }

            Op::MemMapFrame(base, frame, action) => {
                crate::memory::KernelAllocator::try_refill_tcache(7, 0)?;
                self.process.vspace_mut().map_frame(base, frame, action)?;
                Ok(NodeResult::Mapped)
            }

            // Can be MapFrame with base supplied ...
            Op::MemMapDevice(frame, action) => {
                let base = VAddr::from(frame.base.as_u64());
                self.process.vspace_mut()
                    .map_frame(base, frame, action)?;
                    Ok(NodeResult::Mapped)
            }

            Op::MemMapFrameId(base, frame_id, action) => {
                let frame = self.process.get_frame(frame_id)?;
                crate::memory::KernelAllocator::try_refill_tcache(7, 0)?;

                self.process.vspace_mut().map_frame(base, frame, action)?;
                Ok(NodeResult::MappedFrameId(frame.base, frame.size))
            }

            Op::MemUnmap(vaddr) => {
                let mut shootdown_handle = self.process.vspace_mut().unmap(vaddr)?;
                // Figure out which cores are running our current process
                // (this is where we send IPIs later)
                for gtid in self.active_cores.iter() {
                    shootdown_handle.add_core(*gtid);
                }

                Ok(NodeResult::Unmapped(shootdown_handle))
            }

            Op::ProcAllocateCore(pid, Some(gtid), Some(region), entry_point) => {
                let mut executor = self.process.get_executor(region)?;
                let eid = executor.id();
                unsafe {
                    (*executor.vcpu_kernel()).resume_with_upcall = entry_point;
                }
                self.active_cores.push(gtid);


                Ok(NodeResult::CoreAllocated(gtid, executor))
            }

            Op::AllocateFrameToProcess(frame) => {
                let fid = self.process.add_frame(frame)?;
                Ok(NodeResult::FrameId(fid))
            }
        }
    }
}
