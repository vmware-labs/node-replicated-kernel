// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use spin::Lazy;

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
