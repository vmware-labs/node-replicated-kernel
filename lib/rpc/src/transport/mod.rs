pub mod shmem;
pub mod tcp;

pub use shmem::transport::ShmemTransport;
pub use tcp::transport::TCPTransport;

use crate::rpc::{MsgId, RPCError, RPCHeader};

pub trait Transport {
    fn max_send(&self) -> usize;

    fn max_recv(&self) -> usize;

    /// Receive an RPC message from a remote node, blocking
    fn recv_msg(
        &self,
        hdr: &mut RPCHeader,
        recipient_id: Option<MsgId>,
        payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError>;

    /// Send an RPC message to a remote node, blocking
    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError>;

    /// Round-trip message passing.
    fn send_and_recv(
        &self,
        hdr: &mut RPCHeader,
        send_payload: &[&[u8]],
        recv_payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError>;
}
