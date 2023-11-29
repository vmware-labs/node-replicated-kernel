// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(dead_code, warnings)]
use crate::prelude::*;
use core::fmt::Debug;

use crate::arch::kcb;
use alloc::sync::Arc;
use hashbrown::HashMap;
use log::{error, trace};
use nr2::nr::{Dispatch, NodeReplicated, ThreadToken};
use spin::Once;

use lazy_static::lazy_static;

use crate::error::KError;
use crate::memory::VAddr;
use crate::process::{Pid, MAX_PROCESSES};

/// Kernel scheduler / process mgmt. replica
#[thread_local]
pub(crate) static NR_REPLICA_REGISTRATION: Once<ThreadToken> = Once::new();

// Base nr log. The rackscale controller needs to save a reference to this, so it can give
// clones to client so they can create replicas of their own.
#[cfg(feature = "rackscale")]
lazy_static! {
    pub(crate) static ref KERNEL_NODE_INSTANCE: Arc<NodeReplicated<KernelNode>> = {
        use core::num::NonZeroUsize;
        use nr2::nr::AffinityChange;
        use crate::memory::shmem_affinity::mid_to_shmem_affinity;
        use crate::memory::shmem_affinity::local_shmem_affinity;

        if crate::CMDLINE
            .get()
            .map_or(false, |c| c.mode == crate::cmdline::Mode::Controller)
        {
            // Want at least one replica...
            let num_replicas =
                NonZeroUsize::new(core::cmp::max(1, *crate::environment::NUM_MACHINES-1)).unwrap();
            log::info!("NodeReplicated<KernelNode> creating with {} replicas", num_replicas);

            let cur_affinity = {
                let pcm = kcb::per_core_mem();
                let cur_affinity = pcm.physical_memory.borrow().affinity;
                let ret = pcm.set_mem_affinity(local_shmem_affinity()).expect("Can't set affinity");
                cur_affinity
            };

            let nr  = Arc::try_new(
                NodeReplicated::new(num_replicas, |afc: AffinityChange| {
                    log::trace!("Got AffinityChange 1: {:?}", afc);
                    let pcm = kcb::per_core_mem();
                    //log::info!("Got AffinityChange: {:?}", afc);
                    match afc {
                        AffinityChange::Replica(r) => {
                            let affinity = { pcm.physical_memory.borrow().affinity };
                            pcm.set_mem_affinity(mid_to_shmem_affinity(r)).expect("Can't set affinity");
                            return affinity;
                        }
                        AffinityChange::Revert(orig) => {
                            pcm.set_mem_affinity(orig).expect("Can't set affinity");
                            return 0;
                        }
                    }
                })
                .expect("Not enough memory to initialize system"),
            )
            .expect("Not enough memory to initialize system");

            {
                let pcm = kcb::per_core_mem();
                pcm.set_mem_affinity(cur_affinity).expect("Can't set affinity");
            }

            nr
        } else {
            use crate::memory::{paddr_to_kernel_vaddr, PAddr};
            use crate::arch::rackscale::get_shmem_structure::{rpc_get_shmem_structure, ShmemStructure};

            // Get location of the nr log from the controller, who will created them in shared memory
            let mut node_replicated_ptrs = [0u64; 1];
            rpc_get_shmem_structure(ShmemStructure::NrLog, &mut node_replicated_ptrs).expect("Failed to get nr log from controller");
            let nr_ptr = paddr_to_kernel_vaddr(PAddr::from(node_replicated_ptrs[0]));
            let nr_instance = unsafe { Arc::from_raw(nr_ptr.as_u64() as *const NodeReplicated<KernelNode>) };
            nr_instance
        }
    };
}

#[cfg(not(feature = "rackscale"))]
lazy_static! {
    pub(crate) static ref KERNEL_NODE_INSTANCE: Arc<NodeReplicated<KernelNode>> = {
        use core::num::NonZeroUsize;
        use crate::nr::KernelNode;
        use nr2::nr::{AffinityChange, NodeReplicated};

        // Let's go with one replica per NUMA node for now:
        let numa_nodes = core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes());
        let numa_nodes = NonZeroUsize::new(numa_nodes).expect("At least one NUMA node");

        // Create the global operation log and first replica and store it (needs
        // TLS)
        let kernel_node: Arc<NodeReplicated<KernelNode>> = Arc::try_new(
            NodeReplicated::new(numa_nodes, |afc: AffinityChange| {
                let pcm = kcb::per_core_mem();
                match afc {
                    AffinityChange::Replica(r) => {
                        pcm.set_mem_affinity(r).expect("Can't set affinity")
                    }
                    AffinityChange::Revert(orig) => {
                        pcm.set_mem_affinity(orig).expect("Can't set affinity")
                    }
                }
                return 0; // xxx
            })
            .expect("Not enough memory to initialize system"),
        )
        .expect("Not enough memory to initialize system");

        kernel_node
    };
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub(crate) enum ReadOps {
    CurrentProcess(kpi::system::GlobalThreadId),
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
        Option<kpi::system::GlobalThreadId>,
        VAddr,
    ),
    SchedReleaseCore(Pid, Option<atopology::NodeId>, kpi::system::GlobalThreadId),
}

#[derive(Debug, Clone)]
pub(crate) enum NodeResult {
    PidAllocated(Pid),
    PidReturned,
    CoreInfo(CoreInfo),
    CoreAllocated(kpi::system::GlobalThreadId),
    CoreReleased,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoreInfo {
    pub pid: Pid,
    pub entry_point: VAddr,
}

#[derive(Debug, Clone)]
pub(crate) struct KernelNode {
    process_map: HashMap<Pid, ()>,
    scheduler_map: HashMap<kpi::system::GlobalThreadId, CoreInfo>,
}

impl Default for KernelNode {
    fn default() -> KernelNode {
        let k = KernelNode {
            process_map: HashMap::with_capacity(MAX_PROCESSES), // with_capacity(MAX_PROCESSES),
            scheduler_map: HashMap::with_capacity(24), // with_capacity(MAX_CORES), or, for rackscale, with_capacity(MAX_CORES * MAX_MACHINES)
        };
        k
    }
}

impl KernelNode {
    pub(crate) fn synchronize() -> Result<(), KError> {
        KERNEL_NODE_INSTANCE.sync(*NR_REPLICA_REGISTRATION.get().unwrap());
        Ok(())
    }

    pub(crate) fn allocate_core_to_process(
        pid: Pid,
        entry_point: VAddr,
        affinity: Option<atopology::NodeId>,
        gtid: Option<kpi::system::GlobalThreadId>,
    ) -> Result<kpi::system::GlobalThreadId, KError> {
        // todo node id
        crate::nr::NR_REPLICA_REGISTRATION
            .call_once(|| crate::nr::KERNEL_NODE_INSTANCE.register(0).unwrap());

        let op = Op::SchedAllocateCore(pid, affinity, gtid, entry_point);
        let response =
            KERNEL_NODE_INSTANCE.execute_mut(op, *NR_REPLICA_REGISTRATION.get().unwrap());

        match response {
            Ok(NodeResult::CoreAllocated(rgtid)) => Ok(rgtid),
            Err(e) => Err(e),
            Ok(_) => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn release_core_from_process(
        pid: Pid,
        affinity: Option<atopology::NodeId>,
        gtid: kpi::system::GlobalThreadId,
    ) -> Result<(), KError> {
        let op = Op::SchedReleaseCore(pid, affinity, gtid);
        let response =
            KERNEL_NODE_INSTANCE.execute_mut(op, *NR_REPLICA_REGISTRATION.get().unwrap());
        match response {
            Ok(NodeResult::CoreReleased) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => unreachable!("Got unexpected response"),
        }
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
                log::info!("in op alloc pid");
                for i in 0..MAX_PROCESSES {
                    if !self.process_map.contains_key(&i) {
                        log::info!("in op alloc pid 1");
                        self.process_map.try_reserve(1)?;
                        log::info!("in op alloc pid 2");
                        let r = self.process_map.insert(i, ());
                        assert!(r.is_none(), "!contains_key");
                        log::info!("in op alloc pid 3");
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
                #[cfg(not(feature = "rackscale"))]
                assert!(gtid < crate::arch::MAX_CORES, "Invalid gtid");

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
            Op::SchedReleaseCore(pid, _affinity, gtid) => {
                #[cfg(not(feature = "rackscale"))]
                assert!(gtid < crate::arch::MAX_CORES, "Invalid gtid");

                match self.scheduler_map.get(&gtid) {
                    Some(cinfo) => {
                        trace!("Op::SchedReleaseCore pid={}, gtid={}", pid, gtid);

                        if cinfo.pid == pid {
                            let r = self.scheduler_map.remove(&gtid);
                            assert!(r.is_some(), "remove() -> None");
                            Ok(NodeResult::CoreReleased)
                        } else {
                            Err(KError::CoreAllocatedToDifferentProcess)
                        }
                    }
                    None => Err(KError::CoreNotAllocated),
                }
            }
        }
    }
}
