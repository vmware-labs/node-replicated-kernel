// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rpc::cluster_api::RegistrationHandler;
use rpc::rpc_api::RPCHandler;

pub mod close;
pub mod delete;
mod fio;
pub mod getinfo;
pub mod mkdir;
pub mod open_create;
pub mod rename;
pub mod rw;

// Re-export client registration
use self::fio::register_client;
pub const REGISTER_CLIENT: RegistrationHandler = register_client;

// Re-export handlers
use self::open_create::handle_open;
pub const OPEN_HANDLER: RPCHandler = handle_open;

// Re-export marshallers/de-marshallers
pub use self::close::rpc_close;
pub use self::delete::rpc_delete;
pub use self::getinfo::rpc_getinfo;
pub use self::mkdir::rpc_mkdir;
pub use self::open_create::{rpc_create, rpc_open};
pub use self::rename::rpc_rename;
pub use self::rw::{rpc_read, rpc_readat, rpc_write, rpc_writeat};
