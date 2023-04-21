// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abomonation::{decode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use lazy_static::lazy_static;
use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::IpAddress;
use spin::Mutex;

use rpc::api::{RPCHandler, RegistrationHandler};
use rpc::client::Client;
use rpc::rpc::{RPCError, RPCHeader, RPCType};
use rpc::server::Server;
use rpc::transport::TCPTransport;
use rpc::RPCServer;
use vmxnet3::smoltcp::DevQueuePhy;

use crate::error::{KError, KResult};
use crate::transport::ethernet::{init_ethernet_rpc, ETHERNET_IFACE};

pub(crate) mod affinity_alloc;
pub(crate) mod node_registration;
pub(crate) mod resource_alloc;
pub(crate) mod resource_release;

pub(crate) type DCMNodeId = u64;

const DCM_CLIENT_PORT: u16 = 10100;
const DCM_SERVER_PORT: u16 = 10101;

// RPC Handler for client registration on the controller
pub(crate) fn register_dcm_client(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    mut state: Option<(u64, u64)>,
) -> Result<Option<(u64, u64)>, RPCError> {
    log::warn!("register_dcm_client start");
    Ok(None)
}

// Re-export client registration
const DCM_CLIENT_REGISTRAR: RegistrationHandler<Option<(u64, u64)>> = register_dcm_client;

#[derive(Debug, Default)]
#[repr(C)]
struct NodeAssignment {
    alloc_id: u64,
    node: DCMNodeId,
}
unsafe_abomonate!(NodeAssignment: alloc_id, node);

// RPC Handler function for close() RPCs in the controller
fn handle_dcm_node_assignment(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    _state: Option<(u64, u64)>,
) -> Result<Option<(u64, u64)>, RPCError> {
    log::warn!("handle_dcm_node_assignment start");
    // Decode request
    if let Some((req, _)) = unsafe { decode::<NodeAssignment>(payload) } {
        log::debug!(
            "NodeAssignment(alloc_id={:?}), node={:?}",
            req.alloc_id,
            req.node
        );
        hdr.msg_len = 0;
        Ok(Some((req.alloc_id, req.node)))
    } else {
        // Report error if failed to decode request
        Err(RPCError::MalformedRequest)
    }
}

const NODE_ASSIGNMENT_HANDLER: RPCHandler<Option<(u64, u64)>> = handle_dcm_node_assignment;

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
    pub(crate) static ref DCM_INTERFACE: Arc<Mutex<DCMInterface<'static>>> =
        Arc::new(Mutex::new(DCMInterface::new()));
}

pub(crate) struct DCMInterface<'a> {
    pub client: Box<Client>,
    pub server: Box<Server<'a, Option<(u64, u64)>>>,
}

impl DCMInterface<'_> {
    pub fn new() -> DCMInterface<'static> {
        // Create RPC client connecting to DCM
        let client =
            init_ethernet_rpc(IpAddress::v4(172, 31, 0, 20), DCM_CLIENT_PORT, false).unwrap();
        log::info!("Created DCM RPC client!");

        // Create RPC server connecting to DCM
        let transport = Box::try_new(
            TCPTransport::new(None, DCM_SERVER_PORT, Arc::clone(&ETHERNET_IFACE))
                .expect("Failed to create TCP transport"),
        )
        .expect("Out of memory during init");
        let mut server: Box<Server<Option<(u64, u64)>>> =
            Box::try_new(Server::new(transport)).expect("Out of memory during init");
        log::info!("Created DCM RPC server!");

        let _ = server.add_client(&DCM_CLIENT_REGISTRAR, None).unwrap();
        log::info!("Added DCM server RPC client!");

        server
            .register(DCMOps::NodeAssignment as RPCType, &NODE_ASSIGNMENT_HANDLER)
            .unwrap();
        DCMInterface { client, server }
    }
}
