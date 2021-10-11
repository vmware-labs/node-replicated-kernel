// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rpc::rpc_api::RPCHandler;

pub mod open;
pub mod syscalls;

use self::open::handle_open;
pub use self::syscalls::FileIO;

pub const OPEN_HANDLER: RPCHandler = handle_open;
