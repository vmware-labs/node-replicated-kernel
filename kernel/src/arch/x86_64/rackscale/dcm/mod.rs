// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use abomonation::{decode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use smoltcp::iface::Interface;
use smoltcp::wire::IpAddress;
use spin::Mutex;

use kpi::system::MachineId;
use rpc::client::Client;
use rpc::rpc::{RPCError, RPCHeader, RPCType};
use rpc::server::{RPCHandler, RegistrationHandler, Server};
use rpc::transport::TCPTransport;

use crate::error::{KError, KResult};
use crate::transport::ethernet::{init_ethernet_rpc, ETHERNET_IFACE};

pub(crate) mod affinity_alloc;
pub(crate) mod node_registration;
pub(crate) mod resource_alloc;
pub(crate) mod resource_release;

const DCM_CLIENT_PORT: u16 = 10100;
pub(crate) const DCM_SERVER_PORT: u16 = 10101;

// RPC Handler for client registration on the controller
pub(crate) fn register_dcm_client(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    Ok(())
}

// Re-export client registration
pub(crate) const DCM_CLIENT_REGISTRAR: RegistrationHandler = register_dcm_client;

#[derive(Debug, Default)]
#[repr(C)]
struct NodeAssignment {
    alloc_id: u64,
    mid: u64,
}
unsafe_abomonate!(NodeAssignment: alloc_id, mid);

lazy_static! {
    pub(crate) static ref IN_FLIGHT_DCM_ASSIGNMENTS: Arc<Mutex<HashMap<u64, Arc<AtomicU64>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

// RPC Handler function for close() RPCs in the controller
fn handle_dcm_node_assignment(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode request
    if let Some((req, _)) = unsafe { decode::<NodeAssignment>(payload) } {
        log::debug!(
            "NodeAssignment(alloc_id={:?}), mid={:?}",
            req.alloc_id,
            req.mid
        );
        hdr.msg_len = 0;

        let mut assignment_table = IN_FLIGHT_DCM_ASSIGNMENTS.lock();
        match assignment_table.get(&req.alloc_id) {
            Some(assignment) => assignment.store(req.mid, Ordering::SeqCst),
            None => {
                if let Some(entry) =
                    assignment_table.insert(req.alloc_id, Arc::new(AtomicU64::new(req.mid)))
                {
                    unreachable!("If the key wasn't in the table, I should be able to insert without overwriting");
                }
            }
        }

        Ok(())
    } else {
        // Report error if failed to decode request
        Err(RPCError::MalformedRequest)
    }
}

pub(crate) const NODE_ASSIGNMENT_HANDLER: RPCHandler = handle_dcm_node_assignment;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub(crate) enum DCMOps {
    /// Register a node (cores and memory) with DCM
    RegisterNode = 1,
    /// Alloc cores or memory from DCM
    ResourceAlloc = 2,
    /// Release a resource to DCM
    ResourceRelease = 3,
    /// Request shmem of a certain affinity (not for process use)
    AffinityAlloc = 4,
    /// Release shmem of a specific affinity (not yet used)
    AffinityRelease = 5,
    /// Assign a resource to a node
    NodeAssignment = 6,

    Unknown = 7,
}

impl From<RPCType> for DCMOps {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: RPCType) -> DCMOps {
        match op {
            1 => DCMOps::RegisterNode,
            2 => DCMOps::ResourceAlloc,
            3 => DCMOps::ResourceRelease,
            4 => DCMOps::AffinityAlloc,
            5 => DCMOps::AffinityRelease,
            6 => DCMOps::NodeAssignment,
            _ => DCMOps::Unknown,
        }
    }
}
unsafe_abomonate!(DCMOps);

lazy_static! {
    pub(crate) static ref DCM_CLIENT: Arc<Mutex<Client>> = Arc::new(Mutex::new(
        init_ethernet_rpc(IpAddress::v4(172, 31, 0, 20), DCM_CLIENT_PORT, false).unwrap(),
    ));
}
