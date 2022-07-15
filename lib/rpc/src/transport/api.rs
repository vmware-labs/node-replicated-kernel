// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::rpc::{RPCError, RPCHeader};

pub trait Transport {
    // RPC-Agnostic methods for sending/receiving data directly into user-supplied buffers

    /// Maximum per-send payload size
    fn max_send(&self) -> usize;

    /// Maximum per-send payload size
    fn max_recv(&self) -> usize;

    /// Send data to a remote node, blocking
    fn send(&self, send_bufs: &[&[u8]]) -> Result<(), RPCError>;

    /// Send data to a remote node, non-blocking except to avoid partial send
    fn try_send(&self, send_bufs: &[&[u8]]) -> Result<bool, RPCError>;

    /// Receive data from a remote node, blocking
    fn recv(&self, recv_bufs: &mut [&mut [u8]]) -> Result<(), RPCError>;

    /// Receive data from a remote node, non-blocking except to avoid partial receive
    fn try_recv(&self, recv_bufs: &mut [&mut [u8]]) -> Result<bool, RPCError>;

    // RPC-Aware methods for sending/receiving messages directly into user-supplied buffers

    /// Send an RPC message to a remote node, blocking
    fn send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<(), RPCError>;

    /// Send an RPC message to a remote node, non-blocking except to avoid partial send
    fn try_send_msg(&self, hdr: &RPCHeader, payload: &[&[u8]]) -> Result<bool, RPCError>;

    /// Receive an RPC message from a remote node, blocking
    fn recv_msg(&self, hdr: &mut RPCHeader, payload: &mut [&mut [u8]]) -> Result<(), RPCError>;

    /// Receive an RPC message from a remote node, non-blocking except to avoid partial receive
    fn try_recv_msg(
        &self,
        hdr: &mut RPCHeader,
        payload: &mut [&mut [u8]],
    ) -> Result<bool, RPCError>;

    // Methods for cluster management

    /// Controller-side implementation for LITE join_cluster()
    fn client_connect(&mut self) -> Result<(), RPCError>;

    /// Client-side implementation for LITE join_cluster()
    fn server_accept(&self) -> Result<(), RPCError>;
}
