use crate::rpc::RPCError;

pub trait Transport {
    /// Maximum per-send payload size
    fn max_send(&self) -> usize;

    /// Maximum per-send payload size
    fn max_recv(&self) -> usize;

    /// send data to a remote node
    fn send(&self, expected_data: usize, data_buff: &[u8]) -> Result<(), RPCError>;

    /// receive data from a remote node
    fn recv(&self, expected_data: usize, data_buff: &mut [u8]) -> Result<(), RPCError>;

    /// Controller-side implementation for LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError>;

    /// Client-side implementation for LITE join_cluster()
    fn server_accept(&self) -> Result<(), RPCError>;
}
