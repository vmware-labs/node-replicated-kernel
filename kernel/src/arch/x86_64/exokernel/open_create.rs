// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::string::String;
use alloc::vec::Vec;
use log::{debug, warn};

use kpi::io::{FileFlags, FileModes};
use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct OpenReq {
    pub pathname: String,
    pub flags: u64,
    pub modes: u64,
}
unsafe_abomonate!(OpenReq: pathname, flags, modes);

pub fn rpc_create<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    pathname: String,
    flags: u64,
    modes: u64,
) -> Result<(u64, u64), RPCError> {
    rpc_open_create(
        rpc_client,
        pid,
        pathname,
        flags,
        modes,
        FileIO::Create as RPCType,
    )
}

pub fn rpc_open<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    pathname: String,
    flags: u64,
    modes: u64,
) -> Result<(u64, u64), RPCError> {
    rpc_open_create(
        rpc_client,
        pid,
        pathname,
        flags,
        modes,
        FileIO::Open as RPCType,
    )
}

fn rpc_open_create<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    pathname: String,
    flags: u64,
    modes: u64,
    rpc_type: RPCType,
) -> Result<(u64, u64), RPCError> {
    let req = OpenReq {
        pathname: pathname,
        flags: flags,
        modes: modes,
    };
    let mut req_data = Vec::new();
    unsafe { encode(&req, &mut req_data) }.unwrap();
    let mut res = rpc_client.call(pid, rpc_type, req_data).unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Open() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

pub fn handle_open(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse body
    if let Some((req, remaining)) = unsafe { decode::<OpenReq>(payload) } {
        debug!(
            "Open(pathname={:?}, flags={:?}, modes={:?}), local_pid={:?}",
            req.pathname,
            FileFlags::from(req.flags),
            FileModes::from(req.modes),
            local_pid
        );
        if remaining.len() > 0 {
            warn!("Trailing data in payload: {:?}", remaining);
            return construct_error_ret(hdr, payload, RPCError::ExtraData);
        }

        // TODO: FIX DATA COPY
        let mut pathname = req.pathname.clone();
        pathname.push('\0');

        let res = FIORes {
            ret: convert_return(cnrfs::MlnrKernelNode::map_fd(
                local_pid,
                pathname.as_ptr() as u64,
                req.flags,
                req.modes,
            )),
        };
        construct_ret(hdr, payload, res)
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
