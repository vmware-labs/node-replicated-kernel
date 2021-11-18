// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::string::String;
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct DeleteReq {
    pub pathname: String,
}
unsafe_abomonate!(DeleteReq: pathname);

pub fn rpc_delete<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    pathname: String,
) -> Result<(u64, u64), RPCError> {
    debug!("Delete({:?})", pathname);
    let req = DeleteReq { pathname: pathname };
    let mut req_data = Vec::new();
    unsafe { encode(&req, &mut req_data) }.unwrap();
    let mut res = rpc_client
        .call(pid, FileIO::Delete as RPCType, &req_data)
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Delete() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

pub fn handle_delete(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    if let Some((req, _)) = unsafe { decode::<DeleteReq>(payload) } {
        debug!("Delete(name={:?}), local_pid={:?}", req.pathname, local_pid);
        let mut pathname = req.pathname.clone();
        pathname.push('\0');
        let res = FIORes {
            ret: convert_return(cnrfs::MlnrKernelNode::file_delete(
                local_pid,
                pathname.as_ptr() as u64,
            )),
        };
        construct_ret(hdr, payload, res)
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
