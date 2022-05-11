// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::RPCClient;

use super::fio::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct RWReq {
    pub fd: u64,
    pub len: u64,
    pub offset: i64,
}
unsafe_abomonate!(RWReq: fd, len, offset);

pub fn rpc_write(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: u64,
    data: &[u8],
) -> Result<(u64, u64), RPCError> {
    rpc_writeat(rpc_client, pid, fd, -1, data)
}

pub fn rpc_writeat(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: u64,
    offset: i64,
    data: &[u8],
) -> Result<(u64, u64), RPCError> {
    debug!("Write({:?}, {:?})", fd, offset);

    // Constrcut request data
    let req = RWReq {
        fd: fd,
        len: data.len() as u64,
        offset: offset,
    };
    let mut req_data = [0u8; core::mem::size_of::<RWReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];

    // Call readat() or read() RPCs
    if offset == -1 {
        rpc_client
            .call(
                pid,
                FileIO::Write as RPCType,
                &[&req_data, &data],
                &mut [&mut res_data],
            )
            .unwrap();
    } else {
        rpc_client
            .call(
                pid,
                FileIO::WriteAt as RPCType,
                &[&req_data, &data],
                &mut [&mut res_data],
            )
            .unwrap();
    }

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Write() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// This function is just a wrapper for rpc_readat
pub fn rpc_read(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: u64,
    len: u64,
    buff_ptr: &mut [u8],
) -> Result<(u64, u64), RPCError> {
    rpc_readat(rpc_client, pid, fd, len, -1, buff_ptr)
}

pub fn rpc_readat(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: u64,
    len: u64,
    offset: i64,
    buff_ptr: &mut [u8],
) -> Result<(u64, u64), RPCError> {
    debug!("Read({:?}, {:?})", len, offset);

    // Construct request data
    let req = RWReq {
        fd: fd,
        len: len,
        offset: offset,
    };
    let mut req_data = [0u8; core::mem::size_of::<RWReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<FIORes>()];

    // Call Read() or ReadAt() RPC
    if offset == -1 {
        rpc_client
            .call(
                pid,
                FileIO::Read as RPCType,
                &[&req_data],
                &mut [&mut res_data, buff_ptr],
            )
            .unwrap();
    } else {
        rpc_client
            .call(
                pid,
                FileIO::ReadAt as RPCType,
                &[&req_data],
                &mut [&mut res_data, buff_ptr],
            )
            .unwrap();
    }

    // Decode result, if successful, return result
    if let Some((res, remaining)) = unsafe { decode::<FIORes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("Read(At)() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for read() RPCs in the controller
pub fn handle_read(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Extract data needed from the request
    let fd;
    let len;
    let mut offset = -1;
    let mut operation = FileOperation::Read;
    if let Some((req, _)) = unsafe { decode::<RWReq>(payload) } {
        debug!(
            "Read(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
            req.fd, req.len, req.offset, local_pid
        );
        fd = req.fd;
        len = req.len;
        if hdr.msg_type == FileIO::ReadAt as RPCType {
            offset = req.offset;
            operation = FileOperation::ReadAt;
        }
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    // Read directly into payload buffer, at offset after result field & header
    let ret = cnrfs::MlnrKernelNode::file_io(
        operation,
        local_pid,
        fd,
        payload[FIORES_SIZE as usize..].as_mut_ptr() as u64,
        len,
        offset,
    );

    // Read in additional data (e.g., the read data payload)
    let mut additional_data = 0;
    if let Ok((bytes_read, _)) = ret {
        additional_data = bytes_read;
    }

    // Construct return
    let res = FIORes {
        ret: convert_return(ret),
    };
    construct_ret_extra_data(hdr, payload, res, additional_data as u64)
}

// RPC Handler function for write() RPCs in the controller
pub fn handle_write(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Decode request
    if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
        debug!(
            "Write(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
            req.fd, req.len, req.offset, local_pid
        );

        // Call Write() or WriteAt()
        let ret = if hdr.msg_type == FileIO::Write as RPCType {
            cnrfs::MlnrKernelNode::file_io(
                FileOperation::Write,
                local_pid,
                req.fd,
                remaining.as_mut_ptr() as u64,
                req.len,
                -1,
            )
        } else {
            cnrfs::MlnrKernelNode::file_io(
                FileOperation::WriteAt,
                local_pid,
                req.fd,
                remaining.as_mut_ptr() as u64,
                req.len,
                req.offset,
            )
        };

        // Construct return
        let res = FIORes {
            ret: convert_return(ret),
        };
        construct_ret(hdr, payload, res)

    // Return error if failed to decode request
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
