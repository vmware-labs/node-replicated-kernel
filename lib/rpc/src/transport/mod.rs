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

    /// Controller-side implementation for LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError>;

    /// Client-side implementation for LITE join_cluster()
    fn server_accept(&self) -> Result<(), RPCError>;
}
