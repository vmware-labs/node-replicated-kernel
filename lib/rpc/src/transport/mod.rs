pub mod shmem;
mod smoltcp;

pub use self::smoltcp::TCPTransport;
pub use shmem::transport::ShmemTransport;

use crate::rpc::{RPCError, RPCHeader};

pub trait Transport {
    fn max_send(&self) -> usize;

    fn max_recv(&self) -> usize;

    /// Receive an RPC message from a remote node, blocking
    fn recv_msg(&self, hdr: &mut RPCHeader, payload: &mut [&mut [u8]]) -> Result<(), RPCError>;

    /// Receive an RPC message from a remote node, non-blocking except to avoid partial receive
    fn try_recv_msg(
        &self,
        hdr: &mut RPCHeader,
        payload: &mut [&mut [u8]],
    ) -> Result<bool, RPCError>;

    /// Send an RPC message to a remote node, blocking
    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError>;

    /// Send an RPC message to a remote node, non-blocking except to avoid partial send
    fn try_send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<bool, RPCError>;

    /// Client-side method to setup connection to server
    fn client_connect(&mut self) -> Result<(), RPCError>;

    /// Server-side method to setup connection to client
    fn server_accept(&self) -> Result<(), RPCError>;

    /// Round-trip message passing.
    fn send_and_recv(
        &self,
        hdr: &mut RPCHeader,
        send_payload: &[&[u8]],
        recv_payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError>;
}
