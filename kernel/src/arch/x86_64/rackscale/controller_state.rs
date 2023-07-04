// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use arrayvec::ArrayVec;
use lazy_static::lazy_static;
use spin::Mutex;

use kpi::system::{CpuThread, MachineId};

use crate::arch::rackscale::FrameCacheBase;
use crate::arch::MAX_MACHINES;
use crate::memory::backends::MemManager;
use crate::memory::shmem_affinity::{local_shmem_affinity, mid_to_shmem_affinity};
use crate::memory::{mcache::MCache, LARGE_PAGE_SIZE};
use crate::transport::shmem::get_affinity_shmem;

/// TODO(rackscale): think about how we should constrain this?
/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref CONTROLLER_SHMEM_CACHES: Arc<Mutex<ArrayVec<Box<dyn MemManager + Send>, MAX_MACHINES>>> = {
        let mut shmem_caches = ArrayVec::new();
        shmem_caches.push(Box::new(MCache::<2048, 2048>::new_with_frame::<2048, 2048>(
            local_shmem_affinity(),
            get_affinity_shmem(),
        )) as Box<dyn MemManager + Send>);
        for i in 1..MAX_MACHINES {
            shmem_caches.push(Box::new(FrameCacheBase::new(mid_to_shmem_affinity(i)))
                as Box<dyn MemManager + Send>);
        }

        Arc::new(Mutex::new(shmem_caches))
    };
}

/// TODO(rackscale): think about how we should constrain this?
/// TODO(rackscale): want to lock around individual allocators?
/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref SHMEM_MEMSLICE_ALLOCATORS: Arc<Mutex<ArrayVec<MCache<0, 2048>, MAX_MACHINES>>> = {
        let mut shmem_allocators = ArrayVec::new();
        for i in 0..MAX_MACHINES {
            shmem_allocators.push(MCache::<0, 2048>::new(mid_to_shmem_affinity(i + 1)));
        }
        Arc::new(Mutex::new(shmem_allocators))
    };
}

/// This is the state the controller records about each client
pub(crate) struct PerClientState {
    /// The client believes it has this ID
    pub(crate) mid: MachineId,

    /// A list of the hardware threads belonging to this client and whether the thread is scheduler or not
    /// TODO(rackscale, performance): make this a core map??
    pub(crate) hw_threads: Vec<(CpuThread, bool)>,
}

impl PerClientState {
    pub(crate) fn new(mid: MachineId, hw_threads: Vec<(CpuThread, bool)>) -> PerClientState {
        PerClientState { mid, hw_threads }
    }
}

/// This is the state of the controller, including all per-client state
pub(crate) struct ControllerState {
    /// State related to each client.
    per_client_state: ArrayVec<Arc<Mutex<PerClientState>>, MAX_MACHINES>,
}

impl ControllerState {
    pub(crate) fn new(max_clients: usize) -> ControllerState {
        let mut per_client_state = ArrayVec::new();
        for i in 0..max_clients {
            per_client_state.push(Arc::new(Mutex::new(PerClientState::new(i, Vec::new()))));
        }
        ControllerState { per_client_state }
    }

    pub(crate) fn add_client(&mut self, mid: MachineId, threads: &Vec<CpuThread>) {
        let mut client_state = self.per_client_state[mid - 1].lock();
        assert!(client_state.hw_threads.len() == 0);

        client_state
            .hw_threads
            .try_reserve_exact(threads.len())
            .expect("Failed to reserve room in hw threads vector");
        for thread in threads {
            client_state.hw_threads.push((*thread, false));
        }
    }

    pub(crate) fn get_client_state(&self, mid: MachineId) -> &Arc<Mutex<PerClientState>> {
        &self.per_client_state[mid - 1]
    }

    // TODO(rackscale, efficiency): allocates memory on the fly & also has nested loop
    // should be called sparingly or rewritten
    pub(crate) fn get_hardware_threads(&self) -> Vec<CpuThread> {
        let mut hw_threads = Vec::new();
        for client_state in &self.per_client_state {
            let state = client_state.lock();
            hw_threads
                .try_reserve_exact(state.hw_threads.len())
                .expect("Failed to reserve room in hw threads vector");
            for j in 0..state.hw_threads.len() {
                // ignore the thread state and just save the information
                hw_threads.push(state.hw_threads[j].0);
            }
        }
        hw_threads
    }
}
