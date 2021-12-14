// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};

use kpi::io::{FileFlags, FileModes};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct OpenReq {
    pub flags: u64,
    pub modes: u64,
}
unsafe_abomonate!(OpenReq: flags, modes);

pub fn rpc_create<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    pathname: &[u8],
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

pub fn rpc_open<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    pathname: &[u8],
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

fn rpc_open_create<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    pathname: &[u8],
    flags: u64,
    modes: u64,
    rpc_type: RPCType,
) -> Result<(u64, u64), RPCError> {
    debug!("Open({:?}, {:?}, {:?})", pathname, flags, modes);
    let req = OpenReq {
        flags: flags,
        modes: modes,
    };
    let mut req_data = [0u8; core::mem::size_of::<OpenReq>()];
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();
    rpc_client
        .call(pid, rpc_type, &[&req_data, &pathname], &mut [&mut res_data])
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
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

    /*
    let pathname = match core::str::from_utf8(&payload[core::mem::size_of::<OpenReq>()..]) {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid pathname utf8 for request: {:?}, error={:?}", hdr, e);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };
    */

    // Parse body
    let flags;
    let modes;
    if let Some((req, _)) =
        unsafe { decode::<OpenReq>(&mut payload[..core::mem::size_of::<OpenReq>()]) }
    {
        debug!(
            "Open(flags={:?}, modes={:?}), local_pid={:?}",
            FileFlags::from(req.flags),
            FileModes::from(req.modes),
            local_pid
        );
        flags = req.flags;
        modes = req.modes;
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    let res = FIORes {
        ret: convert_return(cnrfs::MlnrKernelNode::map_fd(
            local_pid,
            (&payload[core::mem::size_of::<OpenReq>()..]).as_ptr() as u64,
            flags,
            modes,
        )),
    };
    construct_ret(hdr, payload, res)
}
