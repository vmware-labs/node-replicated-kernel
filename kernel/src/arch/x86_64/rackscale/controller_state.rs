// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use fallible_collections::FallibleVecGlobal;
use hashbrown::HashMap;
use kpi::system::MachineId;
use lazy_static::lazy_static;
use spin::Mutex;
use static_assertions as sa;

use kpi::system::CpuThread;

use crate::arch::rackscale::dcm::DCMNodeId;
use crate::arch::rackscale::processops::core_work::CoreWorkRes;
use crate::memory::mcache::MCache;
use crate::memory::LARGE_PAGE_SIZE;

/// A cache of pages
/// TODO: think about how we should constrain this?
///
/// Used to allocate remote memory (in large chunks)
pub(crate) type FrameCacheMemslice = MCache<2048, 2048>;
sa::const_assert!(core::mem::size_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheMemslice>() <= LARGE_PAGE_SIZE);

/// This is the state the controller records about each client
pub(crate) struct PerClientState {
    /// The client believes it has this ID
    pub(crate) machine_id: MachineId,

    /// Memory manager for the affinity shmem for the client
    pub(crate) shmem_manager: Option<Box<FrameCacheMemslice>>,

    /// A list of the hardware threads belonging to this client and whether the thread is scheduler or not
    pub(crate) hw_threads: Vec<(CpuThread, bool)>,

    /// A list of outstanding core assignments that need to be handled by the remote host
    pub(crate) core_assignments: VecDeque<CoreWorkRes>,
}

impl PerClientState {
    pub(crate) fn new(
        machine_id: MachineId,
        shmem_manager: Option<Box<FrameCacheMemslice>>,
        hw_threads: Vec<(CpuThread, bool)>,
    ) -> PerClientState {
        PerClientState {
            machine_id,
            shmem_manager,
            hw_threads,
            core_assignments: VecDeque::with_capacity(3 as usize),
        }
    }
}

/// This is the state of the controller, including on all clients
pub(crate) struct ControllerState {
    /// Number of clients managed by this controller
    max_clients: usize,

    /// State related to each client. We want fast lookup by both keys
    client_states_by_dcm_node_id: HashMap<DCMNodeId, Arc<Mutex<PerClientState>>>,
    machine_id_to_dcm_node_id: HashMap<MachineId, DCMNodeId>,
}

impl ControllerState {
    pub(crate) fn new(max_clients: usize) -> ControllerState {
        ControllerState {
            max_clients,
            // TODO(hunhoffe): try_with_capacity??
            client_states_by_dcm_node_id: HashMap::with_capacity(max_clients),
            machine_id_to_dcm_node_id: HashMap::with_capacity(max_clients),
        }
    }

    pub(crate) fn add_client(&mut self, dcm_node_id: DCMNodeId, client_state: PerClientState) {
        assert!(!self.client_states_by_dcm_node_id.contains_key(&dcm_node_id));
        assert!(!self
            .machine_id_to_dcm_node_id
            .contains_key(&client_state.machine_id));
        self.machine_id_to_dcm_node_id
            .insert(client_state.machine_id, dcm_node_id);
        self.client_states_by_dcm_node_id
            .insert(dcm_node_id, Arc::new(Mutex::new(client_state)));
    }

    pub(crate) fn get_client_state_by_dcm_node_id(
        &self,
        dcm_node_id: DCMNodeId,
    ) -> &Arc<Mutex<PerClientState>> {
        self.client_states_by_dcm_node_id.get(&dcm_node_id).unwrap()
    }

    pub(crate) fn get_client_state_by_machine_id(
        &self,
        machine_id: MachineId,
    ) -> &Arc<Mutex<PerClientState>> {
        let dcm_node_id = self.machine_id_to_dcm_node_id.get(&machine_id).unwrap();
        self.client_states_by_dcm_node_id.get(dcm_node_id).unwrap()
    }

    // TODO(efficiency): allocates memory on the fly & also has nested loop
    // should be called sparingly or rewritten
    pub(crate) fn get_hardware_threads(&self) -> Vec<CpuThread> {
        let mut hw_threads = Vec::new();
        for client_state in self.client_states_by_dcm_node_id.values() {
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
