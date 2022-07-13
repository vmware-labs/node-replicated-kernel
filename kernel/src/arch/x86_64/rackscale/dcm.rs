use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::BorrowMut;
use core::cell::RefCell;

use rpc::client::Client;
use rpc::transport::TCPTransport;
use rpc::RPCClient;

use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::IpAddress;

use vmxnet3::smoltcp::DevQueuePhy;

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocRequest {
    pub application: u64,
    pub cores: u64,
    pub memslices: u64,
}
pub const REQ_SIZE: usize = core::mem::size_of::<AllocRequest>();

impl AllocRequest {
    /// # Safety
    /// - `self` must be valid AllocRequest
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AllocRequest) as *mut u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocRequest
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts((self as *const AllocRequest) as *const u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocResponse {
    pub alloc_id: u64,
}
pub const RES_SIZE: usize = core::mem::size_of::<AllocResponse>();

impl AllocResponse {
    /// # Safety
    /// - `self` must be valid AllocResponse
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AllocResponse) as *mut u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocResponse
    pub unsafe fn as_bytes(&self) -> &[u8; RES_SIZE] {
        ::core::slice::from_raw_parts((self as *const AllocResponse) as *const u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocAssignment {
    pub alloc_id: u64,
    pub node: u64,
}
pub const ALLOC_LEN: usize = core::mem::size_of::<AllocAssignment>();

impl AllocAssignment {
    /// # Safety
    /// - `self` must be valid AllocAssignment
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts_mut((self as *const AllocAssignment) as *mut u8, ALLOC_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocAssignment
    pub unsafe fn as_bytes(&self) -> &[u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts((self as *const AllocAssignment) as *const u8, ALLOC_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }
}

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
