// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]

use crate::prelude::*;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use hashbrown::HashMap;
use kpi::io::*;
use kpi::process::{FrameId, ProcessInfo};
use kpi::FileOperation;

use node_replication::{Dispatch, ReplicaToken};

use crate::arch::process::{UserPtr, UserSlice};
use crate::arch::{Module, MAX_CORES};
use crate::error::KError;
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::nrproc::MAX_PROCESSES;

use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    CurrentExecutor(atopology::GlobalThreadId),
    Synchronize,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Op<E: Executor> {
    AllocatePid,
    ProcDestroy(Pid),
    /// Assign a core to a process.
    SchedAllocateCore(Pid, Option<atopology::NodeId>, Box<E>),
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
    Synchronized,
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

// TODO(api-ergonomics): Fix ugly execute API
impl<P: Process> KernelNode<P> {
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

    pub fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<(atopology::GlobalThreadId, Eid), KError> {
        let kcb = super::kcb::get_kcb();

        use crate::arch::process::Ring3Process; // XXX
        let (gtid, executor) = crate::nrproc::NrProcess::<Ring3Process>::allocate_core_to_process(
            pid,
            entry_point,
            affinity,
            gtid,
        )?;

        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response =
                    replica.execute_mut(Op::SchedAllocateCore(pid, Some(gtid), executor), *token);

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
            ReadOps::Synchronize => {
                // A NOP that just makes sure we've advanced the replica
                Ok(NodeResult::Synchronized)
            }
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
                // want, find for now, MAX_PROCESSES is tiny
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
            Op::SchedAllocateCore(pid, Some(gtid), executor) => {
                match self.scheduler_map.get(&gtid) {
                    Some(executor) => {
                        error!("Core {} already used by {}", gtid, executor.id());
                        Err(KError::CoreAlreadyAllocated)
                    }
                    None => {
                        let eid = executor.id();
                        self.scheduler_map.insert(gtid, executor.into());
                        Ok(NodeResult::CoreAllocated(gtid, eid))
                    }
                }
            }
            Op::SchedAllocateCore(pid, a, executor) => unimplemented!(),
        }
    }
}
