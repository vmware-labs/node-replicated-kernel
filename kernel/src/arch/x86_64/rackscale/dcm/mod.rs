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

pub(crate) mod node_registration;
pub(crate) mod resource_alloc;
pub(crate) mod resource_release;

use resource_alloc::ALLOC_LEN;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub(crate) enum DCMOps {
    /// Register a node (cores and memory) with DCM
    RegisterNode = 1,
    /// Alloc cores or memory from DCM
    ResourceAlloc = 2,
    /// Release a resource to DCM
    ResourceRelease = 3,

    Unknown = 4,
}

impl From<RPCType> for DCMOps {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: RPCType) -> DCMOps {
        match op {
            1 => DCMOps::RegisterNode,
            2 => DCMOps::ResourceAlloc,
            3 => DCMOps::ResourceRelease,
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
}

impl DCMInterface {
    pub fn new(iface: Arc<Mutex<Interface<'static, DevQueuePhy>>>) -> DCMInterface {
        // Create UDP RX buffer
        let mut sock_vec = Vec::new();
        sock_vec.try_reserve_exact(ALLOC_LEN).unwrap();
        sock_vec.resize(ALLOC_LEN, 0);
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

        DCMInterface { client, udp_handle }
    }
}
