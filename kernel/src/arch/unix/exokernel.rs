use rpc::{
    api::{RPCHandler, RegistrationHandler},
    rpc::{NodeId, RPCError, RPCHeader},
};

pub mod fio {
    pub use kpi::FileOperation as FileIO;
}

pub use fio::FileIO;

fn default(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<(), RPCError> {
    Err(RPCError::NotSupported)
}

fn register(_hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<NodeId, RPCError> {
    Err(RPCError::NotSupported)
}

pub const CLOSE_HANDLER: RPCHandler = default;
pub const DELETE_HANDLER: RPCHandler = default;
pub const GETINFO_HANDLER: RPCHandler = default;
pub const MKDIR_HANDLER: RPCHandler = default;
pub const OPEN_HANDLER: RPCHandler = default;
pub const RENAME_HANDLER: RPCHandler = default;
pub const READ_HANDLER: RPCHandler = default;
pub const WRITE_HANDLER: RPCHandler = default;

pub const CLIENT_REGISTRAR: RegistrationHandler = register;
