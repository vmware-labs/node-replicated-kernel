// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use rpc::rpc::{ClientId, RPCError, RPCHeader};

use super::dcm::node_registration::dcm_register_node;
use crate::memory::LARGE_PAGE_SIZE;
use crate::transport::shmem::SHMEM_REGION;

// RPC Handler for client registration
pub(crate) fn register_client(hdr: &mut RPCHeader, _payload: &[u8]) -> Result<ClientId, RPCError> {
    // TODO: calculate cores and memslices more correctly
    let cores = 64;
    let memslices = SHMEM_REGION.size / LARGE_PAGE_SIZE as u64;

    // Register client resources with DCM, DCM doesn't care about pids, so
    // send w/ dummy pid
    let node_id = dcm_register_node(0, cores, memslices);
    log::info!(
        "Registered client {:?} with {:?} cores and {:?} memslices",
        node_id,
        cores,
        memslices
    );
    hdr.client_id = node_id;
    Ok(node_id)
}
