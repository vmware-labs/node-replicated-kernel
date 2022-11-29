// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::trace;
use spin::Lazy;

use crate::arch::{MAX_CORES, MAX_NUMA_NODES};

/// The core id of the current core (hardware thread).
#[thread_local]
pub(crate) static CORE_ID: Lazy<usize> =
    Lazy::new(|| atopology::MACHINE_TOPOLOGY.current_thread().id as usize);

/// The NUMA node id of the current core (hardware thread).
#[thread_local]
pub(crate) static NODE_ID: Lazy<usize> = Lazy::new(|| {
    atopology::MACHINE_TOPOLOGY
        .current_thread()
        .node_id
        .unwrap_or(0)
});

/// How many cores (hardware threads) we have per NUMA node.
pub(crate) static CORES_PER_NUMA_NODE: Lazy<usize> =
    Lazy::new(|| match atopology::MACHINE_TOPOLOGY.nodes().next() {
        Some(node) => node.threads().count(),
        None => 1,
    });

/// Initialize the machine topology (needs ACPI and alloc):
pub fn init_topology() {
    lazy_static::initialize(&atopology::MACHINE_TOPOLOGY);

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
}
