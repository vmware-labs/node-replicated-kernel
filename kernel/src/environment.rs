// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::trace;
use spin::Lazy;

use kpi::system::new_gtid;

use crate::arch::{MAX_CORES, MAX_MACHINES, MAX_NUMA_NODES};

/// The core id of the current core (hardware thread).
#[thread_local]
pub(crate) static CORE_ID: Lazy<usize> =
    Lazy::new(|| new_gtid(atopology::MACHINE_TOPOLOGY.current_thread().id, *MACHINE_ID));

/// The NUMA node id of the current core (hardware thread).
#[thread_local]
pub(crate) static NODE_ID: Lazy<usize> = Lazy::new(|| {
    atopology::MACHINE_TOPOLOGY
        .current_thread()
        .node_id
        .unwrap_or(0)
});

/// The machine id of the current host.
pub(crate) static MACHINE_ID: Lazy<usize> =
    Lazy::new(|| crate::CMDLINE.get().map_or(0, |c| c.machine_id));

/// Number of machines in the current deployment.
pub(crate) static NUM_MACHINES: Lazy<usize> =
    Lazy::new(|| crate::CMDLINE.get().map_or(1, |c| c.workers) as usize);

/// How many cores (hardware threads) we have per NUMA node.
pub(crate) static CORES_PER_NUMA_NODE: Lazy<usize> =
    Lazy::new(|| match atopology::MACHINE_TOPOLOGY.nodes().next() {
        Some(node) => node.threads().count(),
        None => 1,
    });

/// Initialize the machine topology (needs ACPI and alloc):
pub fn init_topology() {
    lazy_static::initialize(&atopology::MACHINE_TOPOLOGY);
    log::info!("Topology parsed");

    trace!("{:#?}", *atopology::MACHINE_TOPOLOGY);
    let nodes = atopology::MACHINE_TOPOLOGY.num_nodes();
    let cores = atopology::MACHINE_TOPOLOGY.num_threads();
    assert!(
        MAX_NUMA_NODES >= nodes,
        "We don't support more NUMA nodes than `MAX_NUMA_NODES."
    );
    assert!(
        MAX_CORES >= cores,
        "We don't support more cores than `MAX_CORES."
    );
    assert!(
        cnr::MAX_REPLICAS_PER_LOG >= nodes,
        "We don't support as many replicas as we have NUMA nodes."
    );
    assert!(
        node_replication::MAX_REPLICAS_PER_LOG >= nodes,
        "We don't support as many replicas as we have NUMA nodes."
    );
    assert!(
        MAX_MACHINES >= *NUM_MACHINES,
        "We don't support more machines than `MAX_MACHINES`"
    )
}
