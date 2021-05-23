// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::prelude::*;
use alloc::sync::{Arc, Weak};
use core::fmt::Debug;

use hashbrown::HashMap;
use kpi::process::ProcessInfo;

use node_replication::Dispatch;

use crate::arch::MAX_CORES;
use crate::error::KError;
use crate::kcb::{ArchSpecificKcb, Kcb};
use crate::memory::vspace::{MapAction, TlbFlushHandle};
use crate::memory::{PAddr, VAddr};
use crate::process::{Eid, Executor, Pid, Process, ProcessError, MAX_PROCESSES};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    CurrentExecutor(atopology::GlobalThreadId),
}

#[derive(PartialEq, Clone, Debug)]
pub enum Op<E: Executor> {
    AllocatePid,
    ProcDestroy(Pid),
    /// Assign a core to a process.
    SchedAllocateCore(Option<atopology::NodeId>, Box<E>),
}

#[derive(Debug, Clone)]
pub enum NodeResult<E: Executor> {
    PidAllocated(Pid),
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
}

pub struct KernelNode<P: Process> {
    process_map: HashMap<Pid, ()>,
    scheduler_map: HashMap<atopology::GlobalThreadId, Arc<P::E>>,
}

impl<P: Process> Default for KernelNode<P> {
    fn default() -> KernelNode<P> {
        KernelNode {
            process_map: HashMap::with_capacity(MAX_PROCESSES),
            scheduler_map: HashMap::with_capacity(MAX_CORES),
        }
    }
}

impl<P: 'static> KernelNode<P>
where
    P: Process + Default,
{
    pub fn synchronize() -> Result<(), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                replica.sync(*token);
                Ok(())
            })
    }

    pub fn allocate_core_to_process<A>(
        kcb: &mut Kcb<A>,
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<(atopology::GlobalThreadId, Eid), KError>
    where
        A: ArchSpecificKcb<Process = P>,
        P: Process + core::marker::Sync,
    {
        let (gtid, executor) = crate::nrproc::NrProcess::<P>::allocate_core_to_process(
            kcb,
            pid,
            entry_point,
            affinity,
            gtid,
        )?;

        unsafe {
            (*executor.vcpu_kernel()).resume_with_upcall = entry_point;
        }

        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let op: Op<P::E> = Op::SchedAllocateCore(Some(gtid), executor);
                let response = replica.execute_mut(op, *token);

                match &response {
                    Ok(NodeResult::CoreAllocated(rgtid, eid)) => {
                        debug_assert_eq!(gtid, *rgtid);
                        Ok((*rgtid, *eid))
                    }
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }
}

impl<P> Dispatch for KernelNode<P>
where
    P: Process + Default,
{
    type ReadOperation = ReadOps;
    type WriteOperation = Op<P::E>;
    type Response = Result<NodeResult<P::E>, KError>;

    fn dispatch(&self, op: Self::ReadOperation) -> Self::Response {
        match op {
            ReadOps::CurrentExecutor(gtid) => {
                let executor = self
                    .scheduler_map
                    .get(&gtid)
                    .ok_or(KError::NoExecutorForCore)?;
                Ok(NodeResult::Executor(Arc::downgrade(executor)))
            }
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Op::AllocatePid => {
                // TODO(performance): O(n) scan probably not what we really
                // want, fine for now, MAX_PROCESSES is tiny
                for i in 0..MAX_PROCESSES {
                    if !self.process_map.contains_key(&i) {
                        self.process_map.insert(i, ());
                        return Ok(NodeResult::PidAllocated(i));
                    }
                }
                Err(KError::OutOfPids)
            }
            Op::ProcDestroy(pid) => {
                // TODO(correctness): This is just a trivial,
                // wrong implementation at the moment
                match self.process_map.remove(&pid) {
                    Some(_) => Ok(NodeResult::ProcDestroyed),
                    None => {
                        error!("Process not found");
                        Err(ProcessError::NoProcessFoundForPid.into())
                    }
                }
            }
            Op::SchedAllocateCore(Some(gtid), executor) => match self.scheduler_map.get(&gtid) {
                Some(executor) => {
                    error!("Core {} already used by {}", gtid, executor.id());
                    Err(KError::CoreAlreadyAllocated)
                }
                None => {
                    let eid = executor.id();
                    trace!("Op::SchedAllocateCore gtid={} eid={}", gtid, eid);
                    self.scheduler_map.insert(gtid, executor.into());
                    Ok(NodeResult::CoreAllocated(gtid, eid))
                }
            },
            Op::SchedAllocateCore(_gtid, _executor) => unimplemented!(),
        }
    }
}
