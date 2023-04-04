// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::Mutex;
use static_assertions as sa;

use kpi::system::{CpuThread, MachineId};

use crate::arch::rackscale::dcm::DCMNodeId;
use crate::memory::mcache::MCache;
use crate::memory::LARGE_PAGE_SIZE;
use crate::transport::shmem::get_affinity_shmem;

/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref CONTROLLER_AFFINITY_SHMEM: Arc<Mutex<Box<FrameCacheShmem>>> =
        Arc::new(Mutex::new(
            get_affinity_shmem()
                .get_shmem_manager(0)
                .expect("Failed to fetch shmem manager for controller shmem.")
        ));
}

/// A cache of pages
/// TODO(rackscale): think about how we should constrain this?
///
/// Used to allocate remote memory (in large chunks)
pub(crate) type FrameCacheMemslice = MCache<0, 2048>;
sa::const_assert!(core::mem::size_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);

/// A cache of pages
/// TODO(rackscale): think about how we should constrain this?
///
/// Used locally on the controller for, for instance, base logs.
pub(crate) type FrameCacheShmem = MCache<2048, 2048>;
sa::const_assert!(core::mem::size_of::<FrameCacheShmem>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheShmem>() <= LARGE_PAGE_SIZE);

/// This is the state the controller records about each client
pub(crate) struct PerClientState {
    /// The client believes it has this ID
    pub(crate) mid: MachineId,

    /// Memory manager for the affinity shmem for the client
    pub(crate) shmem_manager: Option<Box<FrameCacheMemslice>>,

    /// A list of the hardware threads belonging to this client and whether the thread is scheduler or not
    /// TODO(rackscale, performance): make this a core map??
    pub(crate) hw_threads: Vec<(CpuThread, bool)>,
}

impl PerClientState {
    pub(crate) fn new(
        mid: MachineId,
        shmem_manager: Option<Box<FrameCacheMemslice>>,
        hw_threads: Vec<(CpuThread, bool)>,
    ) -> PerClientState {
        PerClientState {
            mid,
            shmem_manager,
            hw_threads,
        }
    }
}

/// This is the state of the controller, including all per-client state
pub(crate) struct ControllerState {
    /// Maximum number of clients managed by this controller
    max_clients: usize,

    /// State related to each client. We want fast lookup by both keys
    per_client_state: HashMap<DCMNodeId, Arc<Mutex<PerClientState>>>,
    mid_to_dcm_id: HashMap<MachineId, DCMNodeId>,
}

impl ControllerState {
    pub(crate) fn new(max_clients: usize) -> ControllerState {
        ControllerState {
            max_clients,
            // TODO(rackscale, memory): try_with_capacity??
            per_client_state: HashMap::with_capacity(max_clients),
            mid_to_dcm_id: HashMap::with_capacity(max_clients),
        }
    }

    pub(crate) fn add_client(&mut self, dcm_id: DCMNodeId, client_state: PerClientState) {
        assert!(!self.per_client_state.contains_key(&dcm_id));
        assert!(!self.mid_to_dcm_id.contains_key(&client_state.mid));

        self.mid_to_dcm_id.insert(client_state.mid, dcm_id);
        self.per_client_state
            .insert(dcm_id, Arc::new(Mutex::new(client_state)));
    }

    pub(crate) fn get_client_state_by_dcm_id(
        &self,
        dcm_id: DCMNodeId,
    ) -> &Arc<Mutex<PerClientState>> {
        self.per_client_state.get(&dcm_id).unwrap()
    }

    pub(crate) fn mid_to_dcm_id(&self, mid: MachineId) -> DCMNodeId {
        *self.mid_to_dcm_id.get(&mid).unwrap()
    }

    pub(crate) fn get_client_state_by_mid(&self, mid: MachineId) -> &Arc<Mutex<PerClientState>> {
        let dcm_id = self.mid_to_dcm_id.get(&mid).unwrap();
        self.per_client_state.get(dcm_id).unwrap()
    }

    // TODO(efficiency): allocates memory on the fly & also has nested loop
    // should be called sparingly or rewritten
    pub(crate) fn get_hardware_threads(&self) -> Vec<CpuThread> {
        let mut hw_threads = Vec::new();
        for client_state in self.per_client_state.values() {
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
