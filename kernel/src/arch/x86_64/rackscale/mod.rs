// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(warnings)]

use static_assertions as sa;

use rpc::server::{RPCHandler, RegistrationHandler};

use crate::memory::{mcache::MCache, LARGE_PAGE_SIZE};

pub(crate) mod client_state;
pub(crate) mod controller;
pub(crate) mod controller_state;
pub(crate) mod dcm;
pub(crate) mod fileops;
pub(crate) mod get_shmem_frames;
pub(crate) mod get_shmem_structure;
pub(crate) mod kernelrpc;
pub(crate) mod processops;
pub(crate) mod registration;
pub(crate) mod syscalls;
pub(crate) mod systemops;

pub(crate) use self::kernelrpc::KernelRpc;

pub(crate) use self::client_state::CLIENT_STATE;

use self::registration::register_client;

// Re-export client registration
pub(crate) const CLIENT_REGISTRAR: RegistrationHandler = register_client;

// Re-export handlers: file operations
pub(crate) const CLOSE_HANDLER: RPCHandler = fileops::close::handle_close;
pub(crate) const DELETE_HANDLER: RPCHandler = fileops::delete::handle_delete;
pub(crate) const GETINFO_HANDLER: RPCHandler = fileops::getinfo::handle_getinfo;
pub(crate) const MKDIR_HANDLER: RPCHandler = fileops::mkdir::handle_mkdir;
pub(crate) const OPEN_HANDLER: RPCHandler = fileops::open::handle_open;
pub(crate) const RENAME_HANDLER: RPCHandler = fileops::rename::handle_rename;
pub(crate) const READ_HANDLER: RPCHandler = fileops::rw::handle_read;
pub(crate) const WRITE_HANDLER: RPCHandler = fileops::rw::handle_write;

// Re-export handdlers: process operations
pub(crate) const REQUEST_CORE_HANDLER: RPCHandler = processops::request_core::handle_request_core;
pub(crate) const RELEASE_CORE_HANDLER: RPCHandler = processops::release_core::handle_release_core;
pub(crate) const ALLOCATE_PHYSICAL_HANDLER: RPCHandler =
    processops::allocate_physical::handle_allocate_physical;
pub(crate) const RELEASE_PHYSICAL_HANDLER: RPCHandler =
    processops::release_physical::handle_release_physical;
pub(crate) const LOG_HANDLER: RPCHandler = processops::print::handle_log;

// Re-export handlers: system operations
pub(crate) const GET_HARDWARE_THREADS_HANDLER: RPCHandler =
    systemops::get_hardware_threads::handle_get_hardware_threads;

// there aren't syscalls, but are other operations
pub(crate) const GET_SHMEM_STRUCTURE_HANDLER: RPCHandler =
    get_shmem_structure::handle_get_shmem_structure;
pub(crate) const GET_SHMEM_FRAMES_HANDLER: RPCHandler = get_shmem_frames::handle_get_shmem_frames;

/// A cache of base pages
/// TODO(rackscale): think about how we should constrain this?
///
/// Used locally on the client, since only large pages are allocated by the controller.
pub(crate) type FrameCacheBase = MCache<2048, 0>;
sa::const_assert!(core::mem::size_of::<FrameCacheBase>() <= LARGE_PAGE_SIZE);
sa::const_assert!(core::mem::align_of::<FrameCacheBase>() <= LARGE_PAGE_SIZE);
