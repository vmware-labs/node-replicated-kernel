// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::BorrowMut;
use core::cell::RefCell;
use core::convert::TryFrom;
use core::fmt::Debug;
use core2::io::Result as IOResult;
use core2::io::Write;
use lazy_static::lazy_static;
use log::warn;
use rpc::client::Client;
use rpc::rpc::*;
use rpc::transport::TCPTransport;
use rpc::RPCClient;
use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::IpAddress;
use spin::Mutex;
use vmxnet3::smoltcp::DevQueuePhy;

use super::kernelrpc::*;
use crate::arch::rackscale::controller::{get_local_pid, FrameCacheMemslice};
use crate::fallible_string::TryString;
use crate::transport::ethernet::{init_ethernet_rpc, ETHERNET_IFACE};
use crate::transport::shmem::create_shmem_manager;

pub(crate) mod dcm_request;
pub(crate) mod node_registration;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub(crate) enum DCMOps {
    /// Register a node (cores and memory) with DCM
    RegisterNode = 1,
    /// Request cores or memory from DCM
    ResourceRequest = 2,

    Unknown = 3,
}

impl From<RPCType> for DCMOps {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: RPCType) -> DCMOps {
        match op {
            1 => DCMOps::RegisterNode,
            2 => DCMOps::ResourceRequest,
            _ => DCMOps::Unknown,
        }
    }
}
unsafe_abomonate!(DCMOps);

lazy_static! {
    pub(crate) static ref DCM_INTERFACE: Arc<Mutex<DCMInterface>> =
        Arc::new(Mutex::new(DCMInterface::new(Arc::clone(&ETHERNET_IFACE))));
}

pub(crate) struct DCMInterface {
    pub client: Box<Client>,
    pub udp_handle: SocketHandle,
    // TODO: should probably use MemManager, but don't here for simplicity (e.g., send/sync issues with dyn traits)
    pub shmem_manager: Box<FrameCacheMemslice>,
}

impl DCMInterface {
    pub fn new(iface: Arc<Mutex<Interface<'static, DevQueuePhy>>>) -> DCMInterface {
        // Create UDP RX buffer
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(dcm_request::ALLOC_LEN).unwrap();
        sock_vec.resize(dcm_request::ALLOC_LEN, 0);
        let mut metadata_vec = Vec::<UdpPacketMetadata>::new();
        metadata_vec.try_reserve_exact(1).unwrap();
        metadata_vec.resize(1, UdpPacketMetadata::EMPTY);
        let udp_rx_buffer = UdpSocketBuffer::new(metadata_vec, sock_vec);

        // Create UDP TX buffer
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(1).unwrap();
        sock_vec.resize(1, 0);
        let mut metadata_vec = Vec::<UdpPacketMetadata>::new();
        metadata_vec.try_reserve_exact(1).unwrap();
        metadata_vec.resize(1, UdpPacketMetadata::EMPTY);
        let udp_tx_buffer = UdpSocketBuffer::new(metadata_vec, sock_vec);

        // Create UDP socket
        let mut udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        udp_socket.bind(6971).unwrap();
        let udp_handle = iface.lock().add_socket(udp_socket);
        log::info!("Created DCM UDP socket!");

        // Create RPC client connecting to DCM
        let client = init_ethernet_rpc(IpAddress::v4(172, 31, 0, 20), 6970, false).unwrap();
        log::info!("Created DCM RPC client!");

        // Create shmem memory manager
        // TODO: this should really be a result of client connection??
        use crate::memory::LARGE_PAGE_SIZE;
        let shmem_manager = create_shmem_manager(0, 2 * LARGE_PAGE_SIZE as u64, 0)
            .expect("No client shmem manager created.");
        log::info!("DCM shmem manager: {:?}", shmem_manager);

        DCMInterface {
            client,
            udp_handle,
            shmem_manager,
        }
    }
}
