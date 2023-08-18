// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(maybe_uninit_write_slice)]

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

// Setup test logging.
#[cfg(test)]
pub(crate) mod test {
    use std::sync::Once;
    pub(crate) static INIT: Once = Once::new();

    pub(crate) fn setup_test_logging() {
        INIT.call_once(env_logger::init);
    }
}
