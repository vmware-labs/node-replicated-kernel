// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::vec::Vec;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

use crate::arch::exokernel::fio::*;

#[derive(Debug)]
pub struct RWReq {
    pub fd: u64,
    pub len: u64,
    pub offset: i64,
}
unsafe_abomonate!(RWReq: fd, len, offset);

pub fn rpc_write<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    fd: u64,
    data: Vec<u8>,
) -> Result<(u64, u64), RPCError> {
    rpc_writeat(rpc_client, pid, fd, -1, data)
}

pub fn rpc_writeat<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    fd: u64,
    offset: i64,
    data: Vec<u8>,
) -> Result<(u64, u64), RPCError> {
    let req = RWReq {
        fd: fd,
        len: data.len() as u64,
        offset: offset,
    };
    let mut req_data = Vec::new();
    unsafe { encode(&req, &mut req_data) }.unwrap();
    req_data.extend(data);

    let mut res = rpc_client
        .call(pid, FileIO::WriteAt as RPCType, req_data)
        .unwrap();
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Write() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

pub fn rpc_read<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    fd: u64,
    len: u64,
    buff_ptr: &mut [u8],
) -> Result<(u64, u64), RPCError> {
    rpc_readat(rpc_client, pid, fd, len, -1, buff_ptr)
}

pub fn rpc_readat<T: RPCClientAPI>(
    rpc_client: &mut T,
    pid: usize,
    fd: u64,
    len: u64,
    offset: i64,
    buff_ptr: &mut [u8],
) -> Result<(u64, u64), RPCError> {
    let req = RWReq {
        fd: fd,
        len: len,
        offset: offset,
    };
    let mut req_data = Vec::new();
    unsafe { encode(&req, &mut req_data) }.unwrap();

    let mut res = rpc_client
        .call(pid, FileIO::ReadAt as RPCType, req_data)
        .unwrap();
    if let Some((res, data)) = unsafe { decode::<FIORes>(&mut res) } {
        // If result is good, check how much data was returned
        if let Ok((bytes_read, _)) = res.ret {
            if bytes_read != data.len() as u64 {
                warn!(
                    "Unexpected amount of data: bytes_read={:?}, data.len={:?}",
                    bytes_read,
                    data.len()
                );
                return Err(RPCError::MalformedResponse);

            // write data into user supplied buffer
            // TODO: more efficient way to write data?
            } else if bytes_read > 0 {
                debug!("Read buff_ptr[0..{:?}] = {:?}", bytes_read, data);
                buff_ptr[..bytes_read as usize].copy_from_slice(&data);
            }
            debug!("Read() {:?} {:?}", res, buff_ptr);
        }
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}
