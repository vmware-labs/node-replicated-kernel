// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::string::String;
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::rpc_api::RPCClient;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct MkDirReq {
    pub pathname: String,
    pub modes: u64,
}
unsafe_abomonate!(MkDirReq: pathname, modes);

pub fn rpc_mkdir<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    pathname: String,
    modes: u64,
) -> Result<(u64, u64), RPCError> {
    debug!("MkDir({:?})", pathname);
    let req = MkDirReq {
        pathname: pathname,
        modes: modes,
    };
    let mut req_data = Vec::new();
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    unsafe { encode(&req, &mut req_data) }.unwrap();
    rpc_client
        .call(
            pid,
            FileIO::MkDir as RPCType,
            &req_data,
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

    if let Some((req, _)) = unsafe { decode::<MkDirReq>(payload) } {
        debug!(
            "MkDir(pathname={:?}), local_pid={:?}",
            req.pathname, local_pid
        );

        let res = FIORes {
            ret: convert_return(cnrfs::MlnrKernelNode::mkdir(
                local_pid,
                req.pathname.as_ptr() as u64,
                req.modes,
            )),
        };
        construct_ret(hdr, payload, res)
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
