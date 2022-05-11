// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rpc::api::{RPCHandler, RegistrationHandler};

mod error;
mod fio;

mod close;
pub mod controller;
mod delete;
mod getinfo;
mod mkdir;
mod open;
mod rename;
mod rw;
pub mod syscalls;

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
use self::open::handle_open;
pub const OPEN_HANDLER: RPCHandler = handle_open;
use self::rename::handle_rename;
pub const RENAME_HANDLER: RPCHandler = handle_rename;
use self::rw::handle_read;
pub const READ_HANDLER: RPCHandler = handle_read;
use self::rw::handle_write;
pub const WRITE_HANDLER: RPCHandler = handle_write;
