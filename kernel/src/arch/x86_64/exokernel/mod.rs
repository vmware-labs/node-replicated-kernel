// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rpc::rpc_api::{RPCHandler, RegistrationHandler};

pub mod close;
pub mod delete;
mod fio;
pub mod getinfo;
pub mod mkdir;
pub mod open_create;
pub mod rename;
pub mod rw;

pub use fio::FileIO;

// Re-export client registration
use self::fio::register_client;
pub const CLIENT_REGISTRAR: RegistrationHandler = register_client;

// Re-export handlers
use self::close::handle_close;
pub const CLOSE_HANDLER: RPCHandler = handle_close;
use self::delete::handle_delete;
pub const DELETE_HANDLER: RPCHandler = handle_delete;
use self::getinfo::handle_getinfo;
pub const GETINFO_HANDLER: RPCHandler = handle_getinfo;
use self::mkdir::handle_mkdir;
pub const MKDIR_HANDLER: RPCHandler = handle_mkdir;
use self::open_create::handle_open;
pub const OPEN_HANDLER: RPCHandler = handle_open;
use self::rename::handle_rename;
pub const RENAME_HANDLER: RPCHandler = handle_rename;
use self::rw::handle_read;
pub const READ_HANDLER: RPCHandler = handle_read;
use self::rw::handle_write;
pub const WRITE_HANDLER: RPCHandler = handle_write;

// Re-export marshallers/de-marshallers
pub use self::close::rpc_close;
pub use self::delete::rpc_delete;
pub use self::getinfo::rpc_getinfo;
pub use self::mkdir::rpc_mkdir;
pub use self::open_create::{rpc_create, rpc_open};
pub use self::rename::rpc_rename;
pub use self::rw::{rpc_read, rpc_readat, rpc_write, rpc_writeat};
