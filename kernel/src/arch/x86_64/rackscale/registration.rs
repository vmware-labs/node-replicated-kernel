// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;
use fallible_collections::{FallibleVec, FallibleVecGlobal};
use kpi::system::CpuThread;
use log::{debug, error, info, warn};
use rpc::client::Client;
use rpc::rpc::{ClientId, RPCError, RPCHeader};
use rpc::RPCClient;

use super::dcm::node_registration::dcm_register_node;
use crate::arch::rackscale::client::get_num_clients;
use crate::arch::rackscale::controller::{HWTHREADS, HWTHREADS_BUSY, SHMEM_MANAGERS};
use crate::arch::rackscale::systemops::{local_to_gtid, local_to_node_id, local_to_package_id};
use crate::error::KResult;
use crate::memory::LARGE_PAGE_SIZE;
use crate::transport::shmem::{create_shmem_manager, get_affinity_shmem};

#[derive(Debug, Default)]
#[repr(C)]
pub struct ClientRegistrationRequest {
    pub affinity_shmem_offset: u64,
    pub affinity_shmem_size: u64,
    pub num_cores: u64,
}
unsafe_abomonate!(
    ClientRegistrationRequest: affinity_shmem_offset,
    affinity_shmem_size,
    num_cores
);

pub const REQ_SIZE: usize = core::mem::size_of::<ClientRegistrationRequest>();

impl ClientRegistrationRequest {
    /// # Safety
    /// - `self` must be valid ClientRegistrationRequest
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut(
            (self as *const ClientRegistrationRequest) as *mut u8,
            REQ_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid ClientRegistrationRequest
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts(
            (self as *const ClientRegistrationRequest) as *const u8,
            REQ_SIZE,
        )
        .try_into()
        .expect("slice with incorrect length")
    }
}

// Called by client to register client with the controller
pub(crate) fn initialize_client(
    mut client: Box<Client>,
    send_client_data: bool, // This field is used to indicate if init_client() should send ClientRegistrationRequest
) -> KResult<Box<Client>> {
    if send_client_data {
        // Fetch system information
        let (affinity_shmem_offset, affinity_shmem_size) = get_affinity_shmem();
        let hwthreads = atopology::MACHINE_TOPOLOGY.threads();
        let num_threads = atopology::MACHINE_TOPOLOGY.num_threads();

        // Create CpuThreads vector
        let mut return_threads = Vec::try_with_capacity(num_threads)?;
        for hwthread in hwthreads {
            return_threads.try_push(kpi::system::CpuThread {
                id: hwthread.id as usize,
                node_id: hwthread.node_id.unwrap_or(0) as usize,
                package_id: hwthread.package_id as usize,
                core_id: hwthread.core_id as usize,
                thread_id: hwthread.thread_id as usize,
            })?;
        }
        info!("return_threads: {:?}", return_threads);

        // Construct client registration request
        let req = ClientRegistrationRequest {
            affinity_shmem_offset,
            affinity_shmem_size,
            num_cores: atopology::MACHINE_TOPOLOGY.num_threads() as u64,
        };

        // Serialize and send to controller
        let mut req_data = Vec::try_with_capacity(
            core::mem::size_of::<ClientRegistrationRequest>()
                + core::mem::size_of::<CpuThread>() * num_threads
                + core::mem::size_of::<Vec<CpuThread>>(),
        )
        .expect("failed to alloc memory for client registration");
        unsafe { encode(&req, &mut req_data) }.expect("Failed to encode ClientRegistrationRequest");
        unsafe { encode(&return_threads, &mut req_data) }
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
) -> Result<ClientId, RPCError> {
    use crate::memory::LARGE_PAGE_SIZE;

    // Decode client registration request
    if let Some((req, hwthreads_data)) =
        unsafe { decode::<ClientRegistrationRequest>(&mut payload[..hdr.msg_len as usize]) }
    {
        let memslices = req.affinity_shmem_size / (LARGE_PAGE_SIZE as u64);
        info!("Received registration request from client with {:?} cores and shmem {:x?}-{:x?} ({:?} memslices)",
            req.num_cores, req.affinity_shmem_offset, req.affinity_shmem_offset + req.affinity_shmem_size, memslices);

        if let Some((hwthreads, remaining)) = unsafe { decode::<Vec<CpuThread>>(hwthreads_data) } {
            if remaining.len() == 0 {
                // Register client resources with DCM, DCM doesn't care about pids, so
                // send w/ dummy pid
                // TODO: register with one less core, assume init process uses that 1 core
                let client_id = dcm_register_node(0, req.num_cores - 1, memslices);
                info!("Registered client DCM, assigned client_id={:?}", client_id);

                // Create shmem memory manager
                // Probably not most accurate to use client_id for affinity here
                let mut managers = SHMEM_MANAGERS.lock();
                managers[client_id as usize] = create_shmem_manager(
                    req.affinity_shmem_offset,
                    req.affinity_shmem_size,
                    client_id,
                );
                log::info!(
                    "Created shmem manager on behalf of client {:?}: {:?}",
                    client_id,
                    managers[client_id as usize]
                );

                // Record information about the hardware threads
                info!("hwthreads: {:?}", hwthreads);

                let mut rack_threads = HWTHREADS.lock();
                let mut rack_threads_busy = HWTHREADS_BUSY.lock();

                // Make sure there's enough room to store data on whether core is busy or no
                let num_clients = get_num_clients() as usize;
                if rack_threads_busy.capacity() < hwthreads.len() * num_clients + client_id as usize
                {
                    rack_threads_busy
                        .resize_with(hwthreads.len() * num_clients + client_id as usize, || None);
                }

                for hwthread in hwthreads {
                    // set all threads to not busy
                    rack_threads_busy[local_to_gtid(hwthread.id, client_id)] = Some(false);

                    // add thread to global state with global values made globally unique
                    rack_threads.push(CpuThread {
                        // these are global values to make sure no conflicts across rack
                        id: local_to_gtid(hwthread.id, client_id),
                        node_id: local_to_node_id(hwthread.node_id, client_id),
                        package_id: local_to_package_id(hwthread.package_id, client_id),
                        // these are local relative to below, so no work to do
                        core_id: hwthread.core_id,
                        thread_id: hwthread.thread_id,
                    });
                }
                // Let's assume init process is running on hwthread 0 on the client so set that to busy
                rack_threads_busy[local_to_gtid(0, client_id)] = Some(true);

                Ok(client_id)
            } else {
                error!("Extra data in register_client");
                Err(RPCError::MalformedResponse)
            }
        } else {
            error!(
                "Failed to decode client registration hwtheads information during register_client"
            );
            Err(RPCError::MalformedResponse)
        }
    } else {
        error!("Failed to decode client registration request during register_client");
        Err(RPCError::MalformedResponse)
    }
}
