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

pub(crate) const CLOSE_HANDLER: RPCHandler = default;
pub(crate) const DELETE_HANDLER: RPCHandler = default;
pub(crate) const GETINFO_HANDLER: RPCHandler = default;
pub(crate) const MKDIR_HANDLER: RPCHandler = default;
pub(crate) const OPEN_HANDLER: RPCHandler = default;
pub(crate) const RENAME_HANDLER: RPCHandler = default;
pub(crate) const READ_HANDLER: RPCHandler = default;
pub(crate) const WRITE_HANDLER: RPCHandler = default;

pub(crate) const CLIENT_REGISTRAR: RegistrationHandler = register;
