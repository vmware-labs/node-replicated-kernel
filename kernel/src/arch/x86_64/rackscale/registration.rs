// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;
use fallible_collections::{FallibleVec, FallibleVecGlobal};
use kpi::system::{CpuThread, MachineId};
use log::{debug, error, info, warn};
use rpc::client::Client;
use rpc::rpc::{RPCError, RPCHeader};
use rpc::RPCClient;

use super::dcm::{node_registration::dcm_register_node, DCMNodeId};
use crate::arch::rackscale::controller_state::{ControllerState, PerClientState};
use crate::error::KResult;
use crate::memory::LARGE_PAGE_SIZE;
use crate::transport::shmem::{get_affinity_shmem, ShmemRegion};

#[derive(Debug, Default)]
pub(crate) struct ClientRegistrationRequest {
    pub(crate) machine_id: MachineId,
    pub(crate) shmem_region: ShmemRegion,
    pub(crate) num_cores: u64,
}
unsafe_abomonate!(
    ClientRegistrationRequest: machine_id,
    shmem_region,
    num_cores
);

// Called by client to register client with the controller
pub(crate) fn initialize_client(
    mut client: Box<Client>,
    send_client_data: bool, // This field is used to indicate if init_client() should send ClientRegistrationRequest
) -> KResult<Box<Client>> {
    if send_client_data {
        // Fetch system information
        let shmem_region = get_affinity_shmem();
        let hwthreads = atopology::MACHINE_TOPOLOGY.threads();
        let num_threads = atopology::MACHINE_TOPOLOGY.num_threads();

        // Create CpuThreads vector
        let mut client_threads = Vec::try_with_capacity(num_threads)?;
        for hwthread in hwthreads {
            client_threads.try_push(kpi::system::CpuThread {
                id: kpi::system::new_gtid(hwthread.id as usize, *crate::environment::MACHINE_ID),
                node_id: hwthread.node_id.unwrap_or(0) as usize,
                package_id: hwthread.package_id as usize,
                core_id: hwthread.core_id as usize,
                thread_id: hwthread.thread_id as usize,
            })?;
        }
        info!("client_threads: {:?}", client_threads);

        // Construct client registration request
        let req = ClientRegistrationRequest {
            machine_id: *crate::environment::MACHINE_ID,
            shmem_region,
            num_cores: atopology::MACHINE_TOPOLOGY.num_threads() as u64,
        };

        // Serialize and send the registration request to the controller
        let mut req_data = Vec::try_with_capacity(
            core::mem::size_of::<ClientRegistrationRequest>()
                + core::mem::size_of::<CpuThread>() * num_threads
                + core::mem::size_of::<Vec<CpuThread>>(),
        )
        .expect("failed to alloc memory for client registration");
        unsafe { encode(&req, &mut req_data) }.expect("Failed to encode ClientRegistrationRequest");
        unsafe { encode(&client_threads, &mut req_data) }
            .expect("Failed to encode hardware thread vector");
        client.connect(&[&req_data])?;
    } else {
        client.connect(&[&[]])?;
    }
    Ok(client)
}

// RPC Handler for client registration on the controller
pub(crate) fn register_client(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    mut state: ControllerState,
) -> Result<ControllerState, RPCError> {
    use crate::memory::LARGE_PAGE_SIZE;

    // Decode client registration request
    if let Some((req, hwthreads_data)) =
        unsafe { decode::<ClientRegistrationRequest>(&mut payload[..hdr.msg_len as usize]) }
    {
        let memslices = req.shmem_region.size / (LARGE_PAGE_SIZE as u64);
        info!("Received registration request from client {:?} with {:?} cores and shmem {:x?}-{:x?} ({:?} memslices)",
            req.machine_id, req.num_cores, req.shmem_region.base, req.shmem_region.base + req.shmem_region.size, memslices);

        // Parse out hw_threads
        let hw_threads = match unsafe { decode::<Vec<CpuThread>>(hwthreads_data) } {
            Some((hw_threads, [])) => hw_threads,
            Some((_, _)) => {
                error!("Extra data in register_client");
                return Err(RPCError::MalformedResponse);
            }
            None => {
                error!("Failed to decode client registration request during register_client");
                return Err(RPCError::MalformedResponse);
            }
        };

        let mut client_threads = Vec::try_with_capacity(hw_threads.len())
            .expect("Failed to allocate space for client hw thread data");
        for hwthread in hw_threads {
            client_threads.push((*hwthread, false));
        }

        // TODO(correctness): assume client is already running something on core zero (also below)
        client_threads[0] = (client_threads[0].0, true);

        info!("client_threads: {:?}", client_threads);

        // Register client resources with DCM
        // TODO(correctness): subtract 1 because assume client is already running something on core zero
        let dcm_node_id = dcm_register_node(req.num_cores - 1, memslices);
        info!(
            "Registered client DCM, assigned dcm_node_id={:?}",
            dcm_node_id
        );

        // Create shmem memory manager
        let shmem_manager = req.shmem_region.get_shmem_manager();
        log::info!(
            "Created shmem manager on behalf of client {:?}: {:?}",
            req.machine_id,
            shmem_manager
        );

        let client_state = PerClientState::new(req.machine_id, shmem_manager, client_threads);
        state.add_client(dcm_node_id, client_state);

        Ok(state)
    } else {
        error!("Failed to decode client registration request during register_client");
        Err(RPCError::MalformedResponse)
    }
}
