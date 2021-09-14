// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;

#[test]
fn mpsc_example() {
    use std::sync::mpsc::sync_channel;

    use common::MPSCClient;
    use common::MPSCServer;

    let (ctx, crx) = sync_channel(3);
    let (stx, srx) = sync_channel(3);
    let client = MPSCClient::new(crx, stx);
    let server = MPSCServer::new(srx, ctx);

    println!("HI");
}
