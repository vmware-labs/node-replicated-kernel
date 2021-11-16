// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::string::String;
use alloc::vec::Vec;
use core2::io::Write;
use core2::io::Result as IOResult;
use log::debug;

use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

use crate::arch::exokernel::fio::*;

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
    let req = DeleteReq { pathname: pathname };
    let mut req_data = Vec::new();
    unsafe { encode(&req, &mut req_data) }.unwrap();
    let mut res = rpc_client
        .call(pid, FileIO::Delete as RPCType, req_data)
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
