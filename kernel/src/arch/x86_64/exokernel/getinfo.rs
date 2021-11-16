// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::string::String;
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::io::FileInfo;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct GetInfoReq {
    pub name: String,
}
unsafe_abomonate!(GetInfoReq: name);

pub fn rpc_getinfo<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    name: String,
) -> Result<(u64, u64), RPCError> {
    let req = GetInfoReq { name: name };
    let mut req_data = Vec::new();
    unsafe { encode(&req, &mut req_data) }.unwrap();
    let mut res = rpc_client
        .call(pid, FileIO::GetInfo as RPCType, req_data)
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
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

    if let Some((req, remaining)) = unsafe { decode::<GetInfoReq>(payload) } {
        debug!("GetInfo(name={:?}), local_pid={:?}", req.name, local_pid);
        if remaining.len() > 0 {
            warn!("Trailing data in payload: {:?}", remaining);
            return construct_error_ret(hdr, payload, RPCError::ExtraData);
        }
        let fileinfo: FileInfo = Default::default();
        let mut name = req.name.clone();
        // TODO: FIX THIS
        name.push('\0');

        let mut ret = cnrfs::MlnrKernelNode::file_info(
            local_pid,
            name.as_ptr() as u64,
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
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
