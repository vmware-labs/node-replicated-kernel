// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::decode;
use kpi::io::FileInfo;
use log::debug;

use rpc::rpc::*;
use rpc::RPCClient;

use super::fio::*;
use crate::cnrfs;

pub fn rpc_getinfo(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    name: &[u8],
) -> Result<(u64, u64), RPCError> {
    debug!("GetInfo({:?})", name);

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    rpc_client
        .call(
            pid,
            FileIO::GetInfo as RPCType,
            &[&name],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("GetInfo() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for getinfo() RPCs in the controller
pub fn handle_getinfo(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Call local file_info function
    let fileinfo: FileInfo = Default::default();
    let mut ret = cnrfs::MlnrKernelNode::file_info(
        local_pid,
        (&payload).as_ptr() as u64,
        &fileinfo as *const FileInfo as u64,
    );

    // Construct return data
    if ret.is_ok() {
        ret = Ok((fileinfo.ftype, fileinfo.fsize));
    }

    // Construct results from return data
    debug!("GetInfo() returned ret={:?} fileinfo={:?}", ret, fileinfo);
    let res = FIORes {
        ret: convert_return(ret),
    };
    construct_ret(hdr, payload, res)
}
