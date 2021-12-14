// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, error, warn};

use rpc::rpc::*;
use rpc::RPCClient;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct RenameReq {
    pub oldname_len: u64,
}
unsafe_abomonate!(RenameReq: oldname_len);

pub fn rpc_rename<T: RPCClient>(
    rpc_client: &mut T,
    pid: usize,
    oldname: &[u8],
    newname: &[u8],
) -> Result<(u64, u64), RPCError> {
    debug!("Rename({:?}, {:?})", oldname, newname);
    let req = RenameReq {
        oldname_len: oldname.len() as u64,
    };
    let mut req_data = [0u8; core::mem::size_of::<RenameReq>()];
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();
    rpc_client
        .call(
            pid,
            FileIO::FileRename as RPCType,
            &[&req_data, &oldname, &newname],
            &mut [&mut res_data],
        )
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Rename() {:?}", res);
        res.ret
    } else {
        error!("Rename(): Malformed response");
        Err(RPCError::MalformedResponse)
    }
}

pub fn handle_rename(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    let oldname_len = match unsafe { decode::<RenameReq>(payload) } {
        Some((req, _)) => req.oldname_len as usize,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let res = FIORes {
        ret: convert_return(cnrfs::MlnrKernelNode::file_rename(
            local_pid,
            payload[core::mem::size_of::<RenameReq>()
                ..(core::mem::size_of::<RenameReq>() + oldname_len)]
                .as_ptr() as u64,
            payload[(core::mem::size_of::<RenameReq>() + oldname_len)..].as_ptr() as u64,
        )),
    };
    construct_ret(hdr, payload, res)
}
