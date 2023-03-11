// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::prelude::*;
use core::fmt::Debug;

use alloc::sync::Arc;
use hashbrown::HashMap;
use log::{error, trace};
use node_replication::{Dispatch, Replica, ReplicaToken};
use spin::Once;

use crate::arch::MAX_CORES;
use crate::error::KError;
use crate::memory::VAddr;
use crate::process::{Pid, MAX_PROCESSES};

/// Kernel scheduler / process mgmt. replica
#[thread_local]
pub(crate) static NR_REPLICA: Once<(Arc<Replica<'static, KernelNode>>, ReplicaToken)> = Once::new();

#[derive(PartialEq, Clone, Copy, Debug)]
pub(crate) enum ReadOps {
    CurrentProcess(atopology::GlobalThreadId),
}

#[derive(PartialEq, Clone, Debug)]
pub(crate) enum Op {
    /// Allocate a new process (Pid)
    AllocatePid,
    /// Destroy a process
    #[allow(unused)] // TODO
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
pub(crate) enum NodeResult {
    PidAllocated(Pid),
    PidReturned,
    CoreInfo(CoreInfo),
    CoreAllocated(atopology::GlobalThreadId),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoreInfo {
    pub pid: Pid,
    pub entry_point: VAddr,
}

pub(crate) struct KernelNode {
    process_map: HashMap<Pid, ()>,
    scheduler_map: HashMap<atopology::GlobalThreadId, CoreInfo>,
}

impl Default for KernelNode {
    fn default() -> KernelNode {
        KernelNode {
            process_map: HashMap::new(),   // with_capacity(MAX_PROCESSES),
            scheduler_map: HashMap::new(), // with_capacity(MAX_CORES),
        }
    }
}

impl KernelNode {
    pub(crate) fn synchronize() -> Result<(), KError> {
        NR_REPLICA
            .get()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                replica.sync(*token);
                Ok(())
            })
    }

    pub(crate) fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<atopology::GlobalThreadId>,
    ) -> Result<atopology::GlobalThreadId, KError> {
        NR_REPLICA
            .get()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let op = Op::SchedAllocateCore(pid, affinity, gtid, entry_point);
                let response = replica.execute_mut(op, *token);

                match response {
                    Ok(NodeResult::CoreAllocated(rgtid)) => Ok(rgtid),
                    Err(e) => Err(e),
                    Ok(_) => unreachable!("Got unexpected response"),
                }
            })
    }
}

impl Dispatch for KernelNode {
    type ReadOperation<'rop> = ReadOps;
    type WriteOperation = Op;
    type Response = Result<NodeResult, KError>;

    fn dispatch<'rop>(&self, op: Self::ReadOperation<'_>) -> Self::Response {
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
                        self.process_map.try_reserve(1)?;
                        let r = self.process_map.insert(i, ());
                        assert!(r.is_none(), "!contains_key");
                        return Ok(NodeResult::PidAllocated(i));
                    }
                }
                Err(KError::OutOfPids)
            }
            // TODO: better impl, what about scheduler_map?
            Op::FreePid(pid) => match self.process_map.remove(&pid) {
                Some(_) => Ok(NodeResult::PidReturned),
                None => {
                    error!("Process not found");
                    Err(KError::NoProcessFoundForPid)
                }
            },
            Op::SchedAllocateCore(pid, _affinity, Some(gtid), entry_point) => {
                assert!(gtid < MAX_CORES, "Invalid gtid");

                match self.scheduler_map.get(&gtid) {
                    Some(_cinfo) => Err(KError::CoreAlreadyAllocated),
                    None => {
                        trace!("Op::SchedAllocateCore pid={}, gtid={}", pid, gtid);

                        self.scheduler_map.try_reserve(1)?;
                        let r = self
                            .scheduler_map
                            .insert(gtid, CoreInfo { pid, entry_point });
                        assert!(r.is_none(), "get() -> None");

                        Ok(NodeResult::CoreAllocated(gtid))
                    }
                }
            }
            Op::SchedAllocateCore(_pid, _affinity, _gtid, _entry_point) => unimplemented!(),
        }
    }
}
