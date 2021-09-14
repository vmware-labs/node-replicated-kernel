// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;

#[test]
fn mpsc_example() {
    use std::sync::mpsc::sync_channel;
    use std::thread;

    use common::MPSCClient;
    use common::MPSCServer;
    use rpc::rpc::RPCType;
    use rpc::rpc_api::{RPCClientAPI, RPCServerAPI};

    let (ctx, crx) = sync_channel(3);
    let (stx, srx) = sync_channel(3);
    let mut client = MPSCClient::new(crx, stx);
    let mut server = MPSCServer::new(srx, ctx);

    thread::spawn(move || {
        server.rpc_run_server().unwrap();
    });

    let payload = "HELLO".as_bytes().to_vec();
    let response = client.rpc_call(0, RPCType::Unknown, payload).unwrap();
    assert_eq!(response, "HELLO".as_bytes().to_vec());

    let payload = "HELLO2".as_bytes().to_vec();
    let response = client.rpc_call(0, RPCType::Unknown, payload).unwrap();
    assert_eq!(response, "HELLO2".as_bytes().to_vec());
}
