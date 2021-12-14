// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![feature(try_reserve)]

#[macro_use]
extern crate abomonation;

#[cfg(feature = "smoltcp_transport")]
extern crate alloc;

#[cfg(feature = "smoltcp_transport")]
extern crate smoltcp;

#[cfg(feature = "smoltcp_transport")]
extern crate vmxnet3;

pub mod rpc;
pub mod rpc_api;
pub mod rpc_client;
pub mod rpc_server;
pub mod transport;
