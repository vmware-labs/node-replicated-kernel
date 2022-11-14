// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, error, info, warn};
use rpc::client::Client;
use rpc::rpc::{ClientId, RPCError, RPCHeader};
use rpc::RPCClient;

use super::dcm::node_registration::dcm_register_node;
use crate::arch::rackscale::controller::SHMEM_MANAGERS;
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
        let (affinity_shmem_offset, affinity_shmem_size) = get_affinity_shmem();

        let req = ClientRegistrationRequest {
            affinity_shmem_offset,
            affinity_shmem_size,
            num_cores: atopology::MACHINE_TOPOLOGY.num_threads() as u64,
        };
        let mut req_data = [0u8; core::mem::size_of::<ClientRegistrationRequest>()];
        unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();
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
    return if let Some((req, _remaining)) = unsafe { decode::<ClientRegistrationRequest>(payload) }
    {
        let memslices = req.affinity_shmem_size / (LARGE_PAGE_SIZE as u64);
        info!("Received registration request from client with {:?} cores and shmem {:x?}-{:x?} ({:?} memslices)",
            req.num_cores, req.affinity_shmem_offset, req.affinity_shmem_offset + req.affinity_shmem_size, memslices);

        // Register client resources with DCM, DCM doesn't care about pids, so
        // send w/ dummy pid
        let node_id = dcm_register_node(0, req.num_cores, memslices);
        info!("Registered client DCM, assigned client_id={:?}", node_id);

        // Create shmem memory manager
        // Probably not most accurate to use node_id for affinity here
        let mut managers = SHMEM_MANAGERS.lock();
        managers[node_id as usize] =
            create_shmem_manager(req.affinity_shmem_offset, req.affinity_shmem_size, node_id);
        log::info!(
            "Created shmem manager on behalf of client {:?}: {:?}",
            node_id,
            managers[node_id as usize]
        );

        Ok(node_id)
    } else {
        error!("Failed to decode client registration request during register_client");
        Err(RPCError::MalformedResponse)
    };
}
