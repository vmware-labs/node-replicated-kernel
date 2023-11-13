// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use arrayvec::ArrayVec;
use atopology::NodeId;
use lazy_static::lazy_static;
use spin::Mutex;

use kpi::system::{new_gtid, CpuThread, GlobalThreadId, MachineId, MachineThreadId};

use crate::arch::rackscale::FrameCacheBase;
use crate::arch::{MAX_CORES, MAX_MACHINES};
use crate::memory::backends::MemManager;
use crate::memory::mcache::MCache;
use crate::memory::shmem_affinity::{local_shmem_affinity, mid_to_shmem_affinity};
use crate::memory::vspace::{CoreBitMap, CoreBitMapIter};
use crate::transport::shmem::get_affinity_shmem;

/// Caches of memory for use by the controller. The controller cache includes all shmem belonging to the controller,
/// because DCM does not allocate controller shmem.
lazy_static! {
    pub(crate) static ref CONTROLLER_SHMEM_CACHES: Arc<ArrayVec<Mutex<Box<dyn MemManager + Send>>, MAX_MACHINES>> = {
        let mut shmem_caches = ArrayVec::new();
        // TODO(rackscale): think about how we should constrain the mcache?
        shmem_caches.push(Mutex::new(Box::new(MCache::<2048, 65536>::new_with_frame::<2048, 65536>(
            local_shmem_affinity(),
            get_affinity_shmem(),
        )) as Box<dyn MemManager + Send>));
        for i in 1..MAX_MACHINES {
            shmem_caches.push(Mutex::new(Box::new(FrameCacheBase::new(mid_to_shmem_affinity(i)))
                as Box<dyn MemManager + Send>));
        }

        Arc::new(shmem_caches)
    };
}

/// Caches of memslices allocated by the DCM scheduler
lazy_static! {
    pub(crate) static ref SHMEM_MEMSLICE_ALLOCATORS: Arc<ArrayVec<Mutex<MCache<0, 65536>>, MAX_MACHINES>> = {
        // TODO(rackscale): think about how we should constrain the mcache?
        let mut shmem_allocators = ArrayVec::new();
        for i in 1..(MAX_MACHINES + 1) {
            shmem_allocators.push(Mutex::new(MCache::<0, 65536>::new(mid_to_shmem_affinity(i))));
        }
        Arc::new(shmem_allocators)
    };
}

struct ThreadMap {
    pub num_threads: usize,
    pub map: CoreBitMap,
}

impl ThreadMap {
    fn new() -> ThreadMap {
        let map = CoreBitMap { low: 0, high: 0 };
        ThreadMap {
            num_threads: 0,
            map,
        }
    }

    fn init(&mut self, num_threads: usize) {
        // make sure smaller than max size of CoreBitMap
        debug_assert!(num_threads <= (u128::BITS as usize) * 2);

        self.num_threads = num_threads;
        for i in 0..num_threads {
            self.mark_thread_free(i);
        }
    }

    fn mark_thread_free(&mut self, mtid: MachineThreadId) {
        debug_assert!(mtid < self.num_threads);
        self.map.set_bit(mtid, true);
    }

    fn claim_first_free_thread(&mut self) -> Option<MachineThreadId> {
        let mut iter = CoreBitMapIter(self.map);
        if let Some(mtid) = iter.next() {
            if mtid < self.num_threads {
                self.map.set_bit(mtid, false);
                return Some(mtid);
            }
        }
        None
    }
}

/// This is the state the controller records about each client
pub(crate) struct ControllerState {
    /// A composite list of all hardware threads
    hw_threads_all: Arc<Mutex<ArrayVec<CpuThread, { MAX_MACHINES * MAX_CORES }>>>,
    /// Bit maps to keep track of free/busy hw threads. Index is machine_id - 1
    thread_maps: Arc<ArrayVec<Mutex<ThreadMap>, MAX_MACHINES>>,
    /// The NodeId of each thread, organized by client. Index is machine_id - 1
    affinities_per_client: Arc<ArrayVec<Mutex<ArrayVec<NodeId, MAX_CORES>>, MAX_MACHINES>>,
}

impl ControllerState {
    pub(crate) fn init_client_state(&self, mid: MachineId, threads: &Vec<CpuThread>) {
        {
            // We assume that threads are ordered by gtid within the threads list.
            let mut hw_threads = self.hw_threads_all.lock();
            let mut affinities = self.affinities_per_client[mid - 1].lock();
            for thread in threads {
                affinities.push(thread.node_id);
                hw_threads.push(*thread);
            }
        }
        let mut thread_map = self.thread_maps[mid - 1].lock();
        thread_map.init(threads.len());
    }

    pub(crate) fn get_hardware_threads(&self) -> Vec<CpuThread> {
        let hw_threads = self.hw_threads_all.lock();
        // TODO(rackscale, performance): copy is relatiely expensive here
        hw_threads.to_vec()
    }

    // Chooses sequentially for cores on the machine.
    // TODO(rackscale, performance): it should choose in a NUMA-aware fashion for the remote node.
    pub(crate) fn claim_hardware_thread(&self, mid: MachineId) -> Option<(GlobalThreadId, NodeId)> {
        let mut thread_map = self.thread_maps[mid - 1].lock();
        if let Some(mtid) = thread_map.claim_first_free_thread() {
            let affinity = {
                let thread_affinities = self.affinities_per_client[mid - 1].lock();
                thread_affinities[mtid]
            };
            Some((kpi::system::new_gtid(mtid, mid), affinity))
        } else {
            // No threads are free
            None
        }
    }
}

/// State the controller maintains about each client.
lazy_static! {
    pub(crate) static ref CONTROLLER_STATE: ControllerState = {
        let mut affinities_per_client = ArrayVec::new();
        let mut thread_maps = ArrayVec::new();
        for i in 0..MAX_MACHINES {
            affinities_per_client.push(Mutex::new(ArrayVec::new()));
            thread_maps.push(Mutex::new(ThreadMap::new()));
        }
        ControllerState {
            hw_threads_all: Arc::new(Mutex::new(ArrayVec::new())),
            thread_maps: Arc::new(thread_maps),
            affinities_per_client: Arc::new(affinities_per_client),
        }
    };
}
