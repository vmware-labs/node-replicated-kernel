// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;

use super::super::kernelrpc::*;
use super::FileIO;

#[derive(Debug)]
pub(crate) struct RWReq {
    pub pid: usize,
    pub fd: FileDescriptor,
    pub len: u64,
    pub offset: i64,
}
unsafe_abomonate!(RWReq: pid, fd, len, offset);

pub(crate) fn rpc_write(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    data: &[u8],
) -> Result<(u64, u64), RPCError> {
    rpc_writeat(rpc_client, pid, fd, -1, data)
}

pub(crate) fn rpc_writeat(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    offset: i64,
    data: &[u8],
) -> Result<(u64, u64), RPCError> {
    debug!("Write({:?}, {:?})", fd, offset);

    // Constrcut request data
    let req = RWReq {
        pid,
        fd,
        len: data.len() as u64,
        offset,
    };
    let mut req_data = [0u8; core::mem::size_of::<RWReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call readat() or read() RPCs
    let rpc_type = if offset == -1 {
        KernelRpc::Write as RPCType
    } else {
        KernelRpc::WriteAt as RPCType
    };
    rpc_client
        .call(rpc_type, &[&req_data, &data], &mut [&mut res_data])
        .unwrap();

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
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
pub(crate) fn rpc_read(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    buff_ptr: &mut [u8],
) -> Result<(u64, u64), RPCError> {
    rpc_readat(rpc_client, pid, fd, buff_ptr, -1)
}

pub(crate) fn rpc_readat(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    buff_ptr: &mut [u8],
    offset: i64,
) -> Result<(u64, u64), RPCError> {
    debug!("Read({:?}, {:?})", buff_ptr.len(), offset);

    // Construct request data
    let req = RWReq {
        pid,
        fd,
        len: buff_ptr.len() as u64,
        offset,
    };
    let mut req_data = [0u8; core::mem::size_of::<RWReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];

    // Call Read() or ReadAt() RPC
    let rpc_type = if offset == -1 {
        KernelRpc::Read as RPCType
    } else {
        KernelRpc::ReadAt as RPCType
    };
    rpc_client
        .call(
            KernelRpc::ReadAt as RPCType,
            &[&req_data],
            &mut [&mut res_data, buff_ptr],
        )
        .unwrap();

    // Decode result, if successful, return result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
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
pub(crate) fn handle_read(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Extract data needed from the request
    let fd;
    let len;
    let pid;
    let mut offset = -1;
    let mut operation = FileOperation::Read;
    if let Some((req, _)) = unsafe { decode::<RWReq>(payload) } {
        debug!(
            "Read(At)(fd={:?}, len={:?}, offset={:?}), pid={:?}",
            req.fd, req.len, req.offset, req.pid
        );
        fd = req.fd;
        len = req.len;
        pid = req.pid;
        if hdr.msg_type == KernelRpc::ReadAt as RPCType {
            offset = req.offset;
            operation = FileOperation::ReadAt;
        }
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    // Read directly into payload buffer, at offset after result field & header
    let start = KernelRpcRes_SIZE as usize;
    let end = start + len as usize;
    let ret = cnrfs::MlnrKernelNode::file_read(pid, fd, &mut &mut payload[start..end], offset);

    // Read in additional data (e.g., the read data payload)
    let mut additional_data = 0;
    if let Ok((bytes_read, _)) = ret {
        additional_data = bytes_read;
    }

    // Construct return
    let res = KernelRpcRes {
        ret: convert_return(ret),
    };
    construct_ret_extra_data(hdr, payload, res, additional_data as u64)
}

// RPC Handler function for write() RPCs in the controller
pub(crate) fn handle_write(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode request
    if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
        debug!(
            "Write(At)(fd={:?}, len={:?}, offset={:?}), pid={:?}",
            req.fd, req.len, req.offset, req.pid
        );

        // Call Write() or WriteAt()
        let offset = if hdr.msg_type == KernelRpc::Write as RPCType {
            -1
        } else {
            req.offset
        };

        let data = (remaining[..req.len as usize]).try_into()?;
        let ret = cnrfs::MlnrKernelNode::file_write(req.pid, req.fd, data, offset);

        // Construct return
        let res = KernelRpcRes {
            ret: convert_return(ret),
        };
        construct_ret(hdr, payload, res)

    // Return error if failed to decode request
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
