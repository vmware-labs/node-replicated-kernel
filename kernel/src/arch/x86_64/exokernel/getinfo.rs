// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::decode;
use kpi::io::FileInfo;
use log::debug;

use rpc::rpc::*;
use rpc::RPCClient;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

pub fn rpc_getinfo<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    name: &[u8],
) -> Result<(u64, u64), RPCError> {
    debug!("GetInfo({:?})", name);
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    rpc_client
        .call(
            pid,
            FileIO::GetInfo as RPCType,
            &[&name],
            &mut [&mut res_data],
        )
        .unwrap();
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

pub fn handle_getinfo(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    let fileinfo: FileInfo = Default::default();
    let mut ret = cnrfs::MlnrKernelNode::file_info(
        local_pid,
        (&payload).as_ptr() as u64,
        &fileinfo as *const FileInfo as u64,
    );

    if ret.is_ok() {
        ret = Ok((fileinfo.ftype, fileinfo.fsize));
    }

    debug!("GetInfo() returned ret={:?} fileinfo={:?}", ret, fileinfo);
    let res = FIORes {
        ret: convert_return(ret),
    };
    construct_ret(hdr, payload, res)
}
