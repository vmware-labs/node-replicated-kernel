// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::prelude::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Allocator;

use arrayvec::ArrayVec;
use fallible_collections::vec::FallibleVec;
use kpi::process::{FrameId, ProcessInfo};
use kpi::MemType;
use node_replication::{Dispatch, Replica, ReplicaToken};
use spin::Once;

use crate::arch::process::PROCESS_TABLE;
use crate::arch::{Module, MAX_NUMA_NODES};
use crate::error::KError;
use crate::memory::detmem::DA;
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{Eid, Executor, Pid, Process, MAX_PROCESSES};

/// The tokens per core to access the process replicas.
#[thread_local]
pub(crate) static PROCESS_TOKEN: Once<ArrayVec<ReplicaToken, { MAX_PROCESSES }>> = Once::new();

/// Initializes `PROCESS_TOKEN`.
///
/// Should be called on each core.
pub(crate) fn register_thread_with_process_replicas() {
    let node = *crate::environment::NODE_ID;
    debug_assert!(PROCESS_TABLE.len() > node, "Invalid Node ID");

    PROCESS_TOKEN.call_once(|| {
        let mut tokens = ArrayVec::new();
        for pid in 0..MAX_PROCESSES {
            debug_assert!(PROCESS_TABLE[node].len() > pid, "Invalid PID");

            let token = PROCESS_TABLE[node][pid].register();
            tokens.push(token.expect("Need to be able to register"));
        }

        tokens
    });
}

/// Immutable operations on the NrProcess.
#[derive(PartialEq, Clone, Copy, Debug)]
pub(crate) enum ReadOps {
    ProcessInfo,
    MemResolve(VAddr),
}

/// Mutable operations on the NrProcess.
#[derive(PartialEq, Clone, Debug)]
pub(crate) enum Op {
    Load(Pid, &'static Module, Vec<Frame>),

    /// Assign a core to a process.
    AssignExecutor(atopology::NodeId, atopology::GlobalThreadId),

    /// Assign a physical frame to a process (returns a FrameId).
    AllocateFrameToProcess(Frame),

    DispatcherAllocation(Frame),

    MemMapFrame(VAddr, Frame, MapAction),
    MemMapDevice(Frame, MapAction),
    MemMapFrameId(VAddr, FrameId, MapAction),
    MemUnmap(VAddr),
}

/// Possible return values from the NrProcess.
#[derive(Debug, Clone)]
pub(crate) enum NodeResult<E: Executor> {
    Loaded,
    ProcessInfo(ProcessInfo),
    Executor(Box<E>),
    ExecutorsCreated(usize),
    Mapped,
    MappedFrameId(PAddr, usize),
    Unmapped(TlbFlushHandle),
    Resolved(PAddr, MapAction),
    FrameId(usize),
}

/// Advances the replica of all the processes on the current NUMA node.
pub(crate) fn advance_all() {
    let node = *crate::environment::NODE_ID;

    for pid in 0..MAX_PROCESSES {
        let _r = PROCESS_TABLE[node][pid].sync(PROCESS_TOKEN.get().unwrap()[pid]);
    }
}

pub(crate) trait ProcessManager {
    type Process: Process + Sync;

    #[allow(clippy::type_complexity)] // fix this once `associated_type_defaults` works
    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    >;
}

/// A node-replicated process.
pub(crate) struct NrProcess<P: Process, M: Allocator + Clone = alloc::alloc::Global> {
    /// A list of all cores where the current process is running.
    active_cores: Vec<(atopology::GlobalThreadId, Eid), M>,
    /// The process struct itself.
    process: Box<P>,
}

impl<P: Process> NrProcess<P> {
    pub(crate) fn new(process: Box<P>, _da: DA) -> NrProcess<P> {
        NrProcess {
            active_cores: Vec::new(),
            process,
        }
    }
}

impl<P: Process> NrProcess<P> {
    pub(crate) fn load(
        pid: Pid,
        module: &'static Module,
        writeable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::Load(pid, module, writeable_sections),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(NodeResult::Loaded) => Ok(()),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn resolve(pid: Pid, base: VAddr) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        debug_assert!(base.as_u64() < kpi::KERNEL_BASE, "Invalid base");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid]
            .execute(ReadOps::MemResolve(base), PROCESS_TOKEN.get().unwrap()[pid]);
        match response {
            Ok(NodeResult::Resolved(paddr, _rights)) => Ok((paddr.as_u64(), 0x0)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn synchronize(pid: Pid) {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        PROCESS_TABLE[node][pid].sync(PROCESS_TOKEN.get().unwrap()[pid]);
    }

    pub(crate) fn map_device_frame(
        pid: Pid,
        frame: Frame,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::MemMapDevice(frame, action),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(NodeResult::Mapped) => Ok((frame.base.as_u64(), frame.size() as u64)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn unmap(pid: Pid, base: VAddr) -> Result<TlbFlushHandle, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid]
            .execute_mut(Op::MemUnmap(base), PROCESS_TOKEN.get().unwrap()[pid]);
        match response {
            Ok(NodeResult::Unmapped(handle)) => Ok(handle),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn map_frame_id(
        pid: Pid,
        frame_id: FrameId,
        base: VAddr,
        action: MapAction,
    ) -> Result<(PAddr, usize), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::MemMapFrameId(base, frame_id, action),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(NodeResult::MappedFrameId(paddr, size)) => Ok((paddr, size)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn map_frames(
        pid: Pid,
        base: VAddr,
        frames: Vec<Frame>,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let mut virtual_offset = 0;
        for frame in frames {
            let response = PROCESS_TABLE[node][pid].execute_mut(
                Op::MemMapFrame(base + virtual_offset, frame, action),
                PROCESS_TOKEN.get().unwrap()[pid],
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

    pub(crate) fn pinfo(pid: Pid) -> Result<ProcessInfo, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid]
            .execute(ReadOps::ProcessInfo, PROCESS_TOKEN.get().unwrap()[pid]);
        match response {
            Ok(NodeResult::ProcessInfo(pinfo)) => Ok(pinfo),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn allocate_executor<A>(pm: &A, pid: Pid) -> Result<Box<P::E>, KError>
    where
        A: ProcessManager<Process = P>,
        P: Process + core::marker::Sync + 'static,
    {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let gtid = *crate::environment::CORE_ID;
        let node = *crate::environment::NODE_ID;

        let response = pm.process_table()[node][pid].execute_mut(
            Op::AssignExecutor(gtid, node),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(NodeResult::Executor(executor)) => Ok(executor),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn allocate_frame_to_process(pid: Pid, frame: Frame) -> Result<FrameId, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::AllocateFrameToProcess(frame),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(NodeResult::FrameId(fid)) => Ok(fid),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn allocate_dispatchers(pid: Pid, frame: Frame) -> Result<usize, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let node = *crate::environment::NODE_ID;

        let response = PROCESS_TABLE[node][pid].execute_mut(
            Op::DispatcherAllocation(frame),
            PROCESS_TOKEN.get().unwrap()[pid],
        );

        match response {
            Ok(NodeResult::ExecutorsCreated(how_many)) => Ok(how_many),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }
}

impl<P, M> Dispatch for NrProcess<P, M>
where
    P: Process,
    P::E: Copy,
    M: Allocator + Clone,
{
    type WriteOperation = Op;
    type ReadOperation = ReadOps;
    type Response = Result<NodeResult<P::E>, KError>;

    fn dispatch(&self, op: Self::ReadOperation) -> Self::Response {
        match op {
            ReadOps::ProcessInfo => Ok(NodeResult::ProcessInfo(*self.process.pinfo())),
            ReadOps::MemResolve(base) => {
                let (paddr, rights) = self.process.vspace().resolve(base)?;
                Ok(NodeResult::Resolved(paddr, rights))
            }
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Op::Load(pid, module, writeable_sections) => {
                self.process.load(pid, module, writeable_sections)?;
                Ok(NodeResult::Loaded)
            }

            Op::DispatcherAllocation(frame) => {
                let how_many = self.process.allocate_executors(frame)?;
                Ok(NodeResult::ExecutorsCreated(how_many))
            }

            Op::MemMapFrame(base, frame, action) => {
                crate::memory::KernelAllocator::try_refill_tcache(7, 0, MemType::Mem)?;
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
                crate::memory::KernelAllocator::try_refill_tcache(7, 0, MemType::Mem)?;

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

            Op::AssignExecutor(gtid, region) => {
                let executor = self.process.get_executor(region)?;
                let eid = executor.id();
                self.active_cores.try_push((gtid, eid))?;
                Ok(NodeResult::Executor(executor))
            }

            Op::AllocateFrameToProcess(frame) => {
                let fid = self.process.add_frame(frame)?;
                Ok(NodeResult::FrameId(fid))
            }
        }
    }
}
