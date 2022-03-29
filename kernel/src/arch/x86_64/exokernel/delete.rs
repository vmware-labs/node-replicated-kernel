// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::decode;
use log::debug;

use rpc::rpc::*;
use rpc::RPCClient;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

pub fn rpc_delete<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    pathname: &[u8],
) -> Result<(u64, u64), RPCError> {
    debug!("Delete({:?})", pathname);

    // Create buffer for result
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];

    // Call RPC
    rpc_client
        .call(
            pid,
            FileIO::Delete as RPCType,
            &[&pathname],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode result - return result if decoding successful
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Delete() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub fn handle_delete(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Construct and return result
    let res = FIORes {
        ret: convert_return(cnrfs::MlnrKernelNode::file_delete(
            local_pid,
            (&payload).as_ptr() as u64,
        )),
    };
    construct_ret(hdr, payload, res)
}
