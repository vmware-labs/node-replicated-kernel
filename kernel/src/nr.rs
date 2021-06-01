// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::prelude::*;
use core::fmt::Debug;

use hashbrown::HashMap;
use node_replication::Dispatch;

use crate::arch::MAX_CORES;
use crate::error::KError;
use crate::memory::VAddr;
use crate::process::{Pid, ProcessError, MAX_PROCESSES};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReadOps {
    CurrentProcess(atopology::GlobalThreadId),
}

#[derive(PartialEq, Clone, Debug)]
pub enum Op {
    /// Allocate a new process (Pid)
    AllocatePid,
    /// Destroy a process
    FreePid(Pid),
    /// Assign a core to a process
    SchedAllocateCore(
        Pid,
        Option<atopology::NodeId>,
        Option<atopology::GlobalThreadId>,
        VAddr,
    ),
}

#[derive(Debug, Clone)]
pub enum NodeResult {
    PidAllocated(Pid),
    PidReturned,
    CoreInfo(CoreInfo),
    CoreAllocated(atopology::GlobalThreadId),
}

#[derive(Debug, Clone, Copy)]
pub struct CoreInfo {
    pub pid: Pid,
    pub entry_point: VAddr,
}

pub struct KernelNode {
    process_map: HashMap<Pid, ()>,
    scheduler_map: HashMap<atopology::GlobalThreadId, CoreInfo>,
}

impl Default for KernelNode {
    fn default() -> KernelNode {
        KernelNode {
            process_map: HashMap::with_capacity(MAX_PROCESSES),
            scheduler_map: HashMap::with_capacity(MAX_CORES),
        }
    }
}

impl KernelNode {
    pub fn synchronize() -> Result<(), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                replica.sync(*token);
                Ok(())
            })
    }

    pub fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<atopology::GlobalThreadId, KError> {
        let kcb = super::kcb::get_kcb();
        kcb.replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let op = Op::SchedAllocateCore(pid, affinity, gtid, entry_point);
                let response = replica.execute_mut(op, *token);

                match &response {
                    Ok(NodeResult::CoreAllocated(rgtid)) => Ok(*rgtid),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(r) => Err(r.clone()),
                }
            })
    }
}

impl Dispatch for KernelNode {
    type ReadOperation = ReadOps;
    type WriteOperation = Op;
    type Response = Result<NodeResult, KError>;

    fn dispatch(&self, op: Self::ReadOperation) -> Self::Response {
        match op {
            ReadOps::CurrentProcess(gtid) => {
                let core_info = self
                    .scheduler_map
                    .get(&gtid)
                    .ok_or(KError::NoExecutorForCore)?;
                Ok(NodeResult::CoreInfo(*core_info))
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
            Op::FreePid(pid) => {
                // TODO(correctness): This is just a trivial,
                // wrong implementation at the moment
                match self.process_map.remove(&pid) {
                    Some(_) => Ok(NodeResult::PidReturned),
                    None => {
                        error!("Process not found");
                        Err(ProcessError::NoProcessFoundForPid.into())
                    }
                }
            }
            Op::SchedAllocateCore(pid, _affinity, Some(gtid), entry_point) => {
                match self.scheduler_map.get(&gtid) {
                    Some(_cinfo) => Err(KError::CoreAlreadyAllocated),
                    None => {
                        trace!("Op::SchedAllocateCore pid={}, gtid={}", pid, gtid);
                        self.scheduler_map
                            .insert(gtid, CoreInfo { pid, entry_point });
                        Ok(NodeResult::CoreAllocated(gtid))
                    }
                }
            }
            Op::SchedAllocateCore(_pid, _affinity, _gtid, _entry_point) => unimplemented!(),
        }
    }
}
