// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::boxed::Box;
use alloc::vec::Vec;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use fallible_collections::{FallibleVec, FallibleVecGlobal};

use kpi::system::{CpuThread, MachineId};
use rpc::client::Client;
use rpc::rpc::{RPCError, RPCHeader};

use super::dcm::node_registration::dcm_register_node;
use crate::arch::rackscale::controller_state::{CONTROLLER_STATE, SHMEM_MEMSLICE_ALLOCATORS};
use crate::error::KResult;
use crate::memory::backends::AllocatorStatistics;
use crate::memory::mcache::MCache;
use crate::memory::shmem_affinity::mid_to_shmem_affinity;
use crate::memory::{Frame, PAddr, LARGE_PAGE_SIZE};
use crate::transport::shmem::{get_affinity_shmem, get_affinity_shmem_by_mid};

#[derive(Debug, Default)]
pub(crate) struct ClientRegistrationRequest {
    pub(crate) mid: MachineId,
    pub(crate) shmem_region_base: u64,
    pub(crate) shmem_region_size: usize,
    pub(crate) num_cores: u64,
}
unsafe_abomonate!(
    ClientRegistrationRequest: mid,
    shmem_region_base,
    shmem_region_size,
    num_cores
);

// Called by client to register client with the controller
pub(crate) fn initialize_client(
    mut client: Client,
    send_client_data: bool, // This field is used to indicate if init_client() should send ClientRegistrationRequest
) -> KResult<Client> {
    // Don't modify this line without modifying testutils/rackscale_runner.rs
    log::warn!("CLIENT READY");

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
        assert!(client_threads.len() == num_threads);
        log::debug!("client_threads: {:?}", client_threads);

        // Construct client registration request
        let req = ClientRegistrationRequest {
            mid: *crate::environment::MACHINE_ID,
            shmem_region_base: shmem_region.base.as_u64(),
            shmem_region_size: shmem_region.size,
            num_cores: num_threads as u64,
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
pub(crate) fn register_client(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    log::debug!("register_client start");
    // Decode client registration request
    if let Some((req, hwthreads_data)) =
        unsafe { decode::<ClientRegistrationRequest>(&mut payload[..hdr.msg_len as usize]) }
    {
        log::info!(
            "Received registration request from client {:?} with {:?} cores and shmem {:x?}-{:x?}",
            req.mid,
            req.num_cores,
            req.shmem_region_base,
            req.shmem_region_base + req.shmem_region_size as u64
        );

        // Parse out hw_threads
        let hw_threads = match unsafe { decode::<Vec<CpuThread>>(hwthreads_data) } {
            Some((hw_threads, [])) => hw_threads,
            Some((_, _)) => {
                log::error!("Extra data in register_client");
                return Err(RPCError::MalformedResponse);
            }
            None => {
                log::error!("Failed to decode client registration request during register_client");
                return Err(RPCError::MalformedResponse);
            }
        };

        // Make sure the controller and the client are seeing the same shmem addresses.
        {
            let shmem_region = get_affinity_shmem_by_mid(req.mid);
            assert_eq!(
                shmem_region.base.as_u64(),
                req.shmem_region_base,
                "Controller did not assign shmem region the same address as the client"
            );
        }

        // Create shmem memory manager
        let frame = Frame::new(
            PAddr::from(req.shmem_region_base),
            req.shmem_region_size,
            mid_to_shmem_affinity(req.mid),
        );
        let memslices = {
            let mut shmem_manager = &mut SHMEM_MEMSLICE_ALLOCATORS[req.mid as usize - 1].lock();
            shmem_manager.populate_4k_first(frame);
            shmem_manager.free_large_pages() as u64
        };
        log::info!(
            "Created shmem manager on behalf of client {:?}: ({:?} memslices)",
            req.mid,
            memslices
        );

        // Register client resources with DCM
        if dcm_register_node(req.mid, req.num_cores, memslices) {
            log::info!("Registered client with DCM");
        } else {
            log::error!("Failed to register client with DCM");
            return Err(RPCError::RegistrationError);
        }

        CONTROLLER_STATE.init_client_state(req.mid, hw_threads);

        Ok(())
    } else {
        log::error!("Failed to decode client registration request during register_client");
        Err(RPCError::MalformedResponse)
    }
}
