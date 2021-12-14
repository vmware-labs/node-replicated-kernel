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
pub struct CloseReq {
    pub fd: u64,
}
unsafe_abomonate!(CloseReq: fd);

pub fn rpc_close<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    fd: u64,
) -> Result<(u64, u64), RPCError> {
    debug!("Close({:?}", fd);
    let req = CloseReq { fd: fd };
    let mut req_data = [0u8; core::mem::size_of::<CloseReq>()];
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();
    rpc_client
        .call(
            pid,
            FileIO::Close as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Close() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

pub fn handle_close(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    if let Some((req, _)) = unsafe { decode::<CloseReq>(payload) } {
        debug!("Close(fd={:?}), local_pid={:?}", req.fd, local_pid);
        let res = FIORes {
            ret: convert_return(cnrfs::MlnrKernelNode::unmap_fd(local_pid, req.fd)),
        };
        construct_ret(hdr, payload, res)
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}