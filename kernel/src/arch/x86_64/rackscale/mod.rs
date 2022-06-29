// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(warnings)]

use alloc::boxed::Box;
use rpc::api::{RPCClient, RPCHandler, RegistrationHandler};
use spin::{Lazy, Mutex};

mod error;
mod fio;

mod close;
pub(crate) mod controller;
pub(crate) mod dcm;
mod delete;
mod getinfo;
mod mkdir;
mod open;
mod rename;
mod rw;
pub(crate) mod syscalls;

use crate::cmdline::Transport;

/// A handle to an RPC client
///
/// This is used to send requests to a remote control-plane.
#[thread_local]
pub(crate) static RPC_CLIENT: Lazy<Mutex<Box<dyn RPCClient>>> = Lazy::new(|| {
    // Create network stack and instantiate RPC Client
    return if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        Mutex::new(
            crate::transport::ethernet::init_ethernet_rpc(
                smoltcp::wire::IpAddress::v4(172, 31, 0, 11),
                6970,
            )
            .expect("Failed to initialize ethernet RPC"),
        )
    } else {
        // Default is Shmem, even if transport unspecified
        Mutex::new(
            crate::transport::shmem::init_shmem_rpc().expect("Failed to initialize shmem RPC"),
        )
    };
});

pub(crate) use fio::FileIO;

// Re-export client registration
use self::fio::register_client;
pub(crate) const CLIENT_REGISTRAR: RegistrationHandler = register_client;

// Re-export handlers
use self::close::handle_close;
pub(crate) const CLOSE_HANDLER: RPCHandler = handle_close;
use self::delete::handle_delete;
pub(crate) const DELETE_HANDLER: RPCHandler = handle_delete;
use self::getinfo::handle_getinfo;
pub(crate) const GETINFO_HANDLER: RPCHandler = handle_getinfo;
use self::mkdir::handle_mkdir;
pub(crate) const MKDIR_HANDLER: RPCHandler = handle_mkdir;
use self::open::handle_open;
pub(crate) const OPEN_HANDLER: RPCHandler = handle_open;
use self::rename::handle_rename;
pub(crate) const RENAME_HANDLER: RPCHandler = handle_rename;
use self::rw::handle_read;
pub(crate) const READ_HANDLER: RPCHandler = handle_read;
use self::rw::handle_write;
pub(crate) const WRITE_HANDLER: RPCHandler = handle_write;
