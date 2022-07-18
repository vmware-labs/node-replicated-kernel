// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::BorrowMut;
use core::cell::RefCell;
use core::fmt::Debug;
use core2::io::Result as IOResult;
use core2::io::Write;
use log::warn;
use rpc::client::Client;
use rpc::rpc::*;
use rpc::transport::TCPTransport;
use rpc::RPCClient;
use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::IpAddress;
use vmxnet3::smoltcp::DevQueuePhy;

use super::get_local_pid;
use super::kernelrpc::*;
use crate::fallible_string::TryString;

pub(crate) mod dcm_msg;

use dcm_msg::ALLOC_LEN;

pub struct DCMInterface {
    pub client: Box<dyn RPCClient>,
    pub udp_handle: SocketHandle,
}

impl DCMInterface {
    pub fn new(iface: Arc<RefCell<Interface<'static, DevQueuePhy>>>) -> DCMInterface {
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
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        let udp_handle = (*iface).borrow_mut().add_socket(udp_socket);
        log::info!("Created UDP socket!");

        // Create and connect RPC DCM Client
        let rpc_transport = Box::try_new(TCPTransport::new(
            Some(IpAddress::v4(172, 31, 0, 20)),
            6970,
            Arc::clone(&iface),
        ))
        .expect("Failed to initialize TCP transport");

        let mut client =
            Box::try_new(Client::new(rpc_transport)).expect("Failed to create ethernet RPC client");
        client.connect().expect("Failed to connect RPC client");
        log::info!("Started RPC client!");

        DCMInterface { client, udp_handle }
    }
}
