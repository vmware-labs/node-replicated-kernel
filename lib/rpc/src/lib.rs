// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![feature(allocator_api)]

#[cfg(any(test, feature = "std"))]
extern crate std;

extern crate abomonation;
extern crate alloc;
extern crate core2;
extern crate smoltcp;
extern crate vmxnet3;

pub mod client;
pub mod rpc;
pub mod server;
pub mod transport;
