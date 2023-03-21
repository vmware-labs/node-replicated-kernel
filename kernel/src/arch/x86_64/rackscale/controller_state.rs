// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use fallible_collections::FallibleVecGlobal;
use hashbrown::HashMap;
use kpi::system::MachineId;
use lazy_static::lazy_static;
use spin::Mutex;
use static_assertions as sa;

use kpi::system::CpuThread;

use crate::arch::rackscale::dcm::DCMNodeId;
use crate::arch::rackscale::processops::core_work::CoreWorkRes;
use crate::fallible_string::FallibleString;
use crate::memory::mcache::MCache;
use crate::memory::LARGE_PAGE_SIZE;
use crate::transport::shmem::{get_affinity_shmem, SHMEM_DEVICE};

/// Global state about the local rackscale client
lazy_static! {
    pub(crate) static ref CONTROLLER_AFFINITY_SHMEM: Arc<Mutex<Box<FrameCacheShmem>>> =
        Arc::new(Mutex::new(
            get_affinity_shmem()
                .get_shmem_manager(SHMEM_DEVICE.region.base)
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
    pub(crate) machine_id: MachineId,

    /// Memory manager for the affinity shmem for the client
    pub(crate) shmem_manager: Option<Box<FrameCacheMemslice>>,

    /// A list of the hardware threads belonging to this client and whether the thread is scheduler or not
    pub(crate) hw_threads: Vec<(CpuThread, bool)>,

    /// A list of outstanding core assignments that need to be handled by the remote host
    pub(crate) core_assignments: VecDeque<CoreWorkRes>,

    /// Used to control serial prints from the client
    print_buffer: RefCell<String>,
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
            print_buffer: RefCell::new(
                String::try_with_capacity(128)
                    .expect("Not enough memory to initialize per-client state"),
            ),
        }
    }

    /// This is mostly copied from arch/x86_64/serial.rs
    /// A poor mans line buffer scheme
    ///
    /// Buffers things until there is a newline in the `buffer` OR we've
    /// exhausted the available `print_buffer` space, then print everything out.
    pub(crate) fn buffered_print(&self, buffer: &str) {
        // A poor mans line buffer scheme:
        match self.print_buffer.try_borrow_mut() {
            Ok(mut kbuf) => match buffer.find("\n") {
                Some(idx) => {
                    let (low, high) = buffer.split_at(idx + 1);

                    // Remove last character, which should be the newline since log already has a return.
                    let low_print = if low.len() > 0 {
                        &low[0..low.len() - 1]
                    } else {
                        low
                    };
                    log::info!("Client{}: {}{}", self.machine_id, kbuf, low_print);
                    kbuf.clear();

                    // Avoid realloc of the kbuf if capacity can't fit `high`
                    // kbuf.len() will be 0 but we keep it for robustness
                    if high.len() <= kbuf.capacity() - kbuf.len() {
                        kbuf.push_str(high);
                    } else {
                        log::info!("Client{}: {}", self.machine_id, high);
                    }
                }
                None => {
                    // Avoid realloc of the kbuf if capacity can't fit `buffer`
                    if buffer.len() > kbuf.capacity() - kbuf.len() {
                        log::info!("Client{}: {}{}", self.machine_id, kbuf, buffer);
                        kbuf.clear();
                    } else {
                        kbuf.push_str(buffer);
                    }
                }
            },
            // BorrowMutError can happen (e.g., we're in a panic interrupt
            // handler or in the gdb debug handler while we were printing in the
            // kernel code) so we just print the current buffer to have some
            // output which might get mangled with other output but mangled
            // output is still better than no output, am I right?
            Err(_e) => {
                log::info!("Client{}: {}", self.machine_id, buffer);
            }
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

    pub(crate) fn machine_id_to_dcm_node_id(&self, machine_id: MachineId) -> DCMNodeId {
        *self.machine_id_to_dcm_node_id.get(&machine_id).unwrap()
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
