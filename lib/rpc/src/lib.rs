// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[macro_use]
extern crate abomonation;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "smoltcp_transport")]
extern crate smoltcp;

#[cfg(feature = "smoltcp_transport")]
extern crate vmxnet3;

pub mod api;
pub mod client;
pub mod rpc;
pub mod server;
pub mod transport;

pub use api::{RPCClient, RPCServer};
