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

use lazy_static::lazy_static;
use node_replication::{Dispatch, Log, Replica, ReplicaToken};

use crate::arch::process::{Ring3Executor, Ring3Process, UserPtr, UserSlice};
use crate::arch::Module;
use crate::error::KError;
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};

use crate::kcb::{self, ArchSpecificKcb};

/// How many (concurrent) processes the systems supports.
pub const MAX_PROCESSES: usize = 12;

lazy_static! {
    pub static ref PROCESS_TABLE: Vec<Vec<Arc<Replica<'static, NrProcess<Ring3Process>>>>> = {
        let numa_nodes = atopology::MACHINE_TOPOLOGY.num_nodes();
        let numa_nodes = if numa_nodes == 0 { numa_nodes + 1 } else { numa_nodes }; // Want at least one replica...

        let mut numa_cache = Vec::with_capacity(numa_nodes);
        for n in 0..numa_nodes {
            let process_replicas = Vec::with_capacity(MAX_PROCESSES);
            numa_cache.push(process_replicas)
        }

        for pid in 0..MAX_PROCESSES {
                let log = Arc::new(Log::<<NrProcess<Ring3Process> as Dispatch>::WriteOperation>::new(
                    2 * 1024 * 1024,
                ));

            for node in 0..numa_nodes {
                let kcb = kcb::get_kcb();
                kcb.set_allocation_affinity(node as atopology::NodeId);
                numa_cache[node].push(Replica::<NrProcess<Ring3Process>>::new(&log));
                debug_assert_eq!(kcb.arch.node(), 0, "Expect initialization to happen on node 0.");
                kcb.set_allocation_affinity(0 as atopology::NodeId);
            }
        }

        numa_cache
    };
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    ProcessInfo,
    MemResolve(VAddr),
    Synchronize,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Op {
    ProcRaiseIrq,
    Load(Pid, &'static Module, Vec<Frame>),

    /// Assign a core to a process.
    ProcAllocateCore(
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
    Loaded,
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
    active_cores: Vec<(atopology::GlobalThreadId, Eid)>,
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
    pub fn load(
        pid: Pid,
        module: &'static Module,
        writeable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::Load(pid, module, writeable_sections),
            kcb.process_token[pid],
        );
        match response {
            Ok(NodeResult::Loaded) => Ok(()),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn resolve(pid: Pid, base: VAddr) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        debug_assert!(base.as_u64() < kpi::KERNEL_BASE, "Invalid base");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response =
            PROCESS_TABLE[node][pid].execute(ReadOps::MemResolve(base), kcb.process_token[pid]);
        match response {
            Ok(NodeResult::Resolved(paddr, rights)) => Ok((paddr.as_u64(), 0x0)),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn synchronize(pid: Pid) -> Result<(), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response =
            PROCESS_TABLE[node][pid].execute(ReadOps::Synchronize, kcb.process_token[pid]);
        match response {
            Ok(NodeResult::Synchronized) => Ok(()),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn map_device_frame(
        pid: Pid,
        frame: Frame,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response = PROCESS_TABLE[node][pid]
            .execute_mut(Op::MemMapDevice(frame, action), kcb.process_token[pid]);
        match response {
            Ok(NodeResult::Mapped) => Ok((frame.base.as_u64(), frame.size() as u64)),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn unmap(pid: Pid, base: VAddr) -> Result<TlbFlushHandle, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response =
            PROCESS_TABLE[node][pid].execute_mut(Op::MemUnmap(base), kcb.process_token[pid]);
        match response {
            Ok(NodeResult::Unmapped(handle)) => Ok(handle),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn map_frame_id(
        pid: Pid,
        frame_id: FrameId,
        base: VAddr,
        action: MapAction,
    ) -> Result<(PAddr, usize), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::MemMapFrameId(base, frame_id, action),
            kcb.process_token[pid],
        );
        match response {
            Ok(NodeResult::MappedFrameId(paddr, size)) => Ok((paddr, size)),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn map_frames(
        pid: Pid,
        base: VAddr,
        frames: Vec<Frame>,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let mut virtual_offset = 0;
        for frame in frames {
            let response = PROCESS_TABLE[node][pid].execute_mut(
                Op::MemMapFrame(base + virtual_offset, frame, action),
                kcb.process_token[pid],
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
            }

            virtual_offset += frame.size();
        }

        Ok((base.as_u64(), virtual_offset as u64))
    }

    pub fn pinfo(pid: Pid) -> Result<ProcessInfo, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response =
            PROCESS_TABLE[node][pid].execute(ReadOps::ProcessInfo, kcb.process_token[pid]);
        match response {
            Ok(NodeResult::ProcessInfo(pinfo)) => Ok(pinfo),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<(atopology::GlobalThreadId, Box<Ring3Executor>), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::ProcAllocateCore(gtid, affinity, entry_point),
            kcb.process_token[pid],
        );
        match response {
            Ok(NodeResult::CoreAllocated(rgtid, executor)) => {
                let _r = gtid.map(|gtid| debug_assert_eq!(gtid, rgtid));
                Ok((rgtid, executor))
            }
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn allocate_frame_to_process(pid: Pid, frame: Frame) -> Result<FrameId, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response = PROCESS_TABLE[node][pid]
            .execute_mut(Op::AllocateFrameToProcess(frame), kcb.process_token[pid]);
        match response {
            Ok(NodeResult::FrameId(fid)) => Ok(fid),
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub fn allocate_dispatchers(pid: Pid, frame: Frame) -> Result<usize, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let kcb = super::kcb::get_kcb();
        let node = kcb.arch.node();

        let response = PROCESS_TABLE[node][pid]
            .execute_mut(Op::DispatcherAllocation(frame), kcb.process_token[pid]);

        match response {
            Ok(NodeResult::ExecutorsCreated(how_many)) => {
                assert!(how_many > 0);
                Ok(how_many)
            }
            Err(e) => Err(e.clone()),
            _ => unreachable!("Got unexpected response"),
        }
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
            ReadOps::ProcessInfo => Ok(NodeResult::ProcessInfo(*self.process.pinfo())),
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

            Op::Load(pid, module, writeable_sections) => {
                self.process.load(pid, module, writeable_sections)?;
                Ok(NodeResult::Loaded)
            }

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
                self.process.vspace_mut().map_frame(base, frame, action)?;
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
                for (gtid, _eid) in self.active_cores.iter() {
                    shootdown_handle.add_core(*gtid);
                }

                Ok(NodeResult::Unmapped(shootdown_handle))
            }

            Op::ProcAllocateCore(Some(gtid), Some(region), entry_point) => {
                let mut executor = self.process.get_executor(region)?;
                let eid = executor.id();
                unsafe {
                    (*executor.vcpu_kernel()).resume_with_upcall = entry_point;
                }
                self.active_cores.push((gtid, eid));

                Ok(NodeResult::CoreAllocated(gtid, executor))
            }
            Op::ProcAllocateCore(a, b, entry_point) => unimplemented!("ProcAllocateCore"),

            Op::AllocateFrameToProcess(frame) => {
                let fid = self.process.add_frame(frame)?;
                Ok(NodeResult::FrameId(fid))
            }
        }
    }
}
