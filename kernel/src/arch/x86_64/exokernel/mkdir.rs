// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::rpc_api::RPCClient;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct MkDirReq {
    pub modes: u64,
}
unsafe_abomonate!(MkDirReq: modes);

pub fn rpc_mkdir<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    pathname: &[u8],
    modes: u64,
) -> Result<(u64, u64), RPCError> {
    debug!("MkDir({:?})", pathname);
    let req = MkDirReq { modes: modes };
    let mut req_data = [0u8; core::mem::size_of::<MkDirReq>()];
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();
    rpc_client
        .call(
            pid,
            FileIO::MkDir as RPCType,
            &[&req_data, &pathname],
            &mut [&mut res_data],
        )
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("MkDir() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

pub fn handle_mkdir(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    let modes = match unsafe { decode::<MkDirReq>(payload) } {
        Some((req, _)) => req.modes,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let res = FIORes {
        ret: convert_return(cnrfs::MlnrKernelNode::mkdir(
            local_pid,
            (&payload[..core::mem::size_of::<MkDirReq>()]).as_ptr() as u64,
            modes,
        )),
    };
    construct_ret(hdr, payload, res)
}
