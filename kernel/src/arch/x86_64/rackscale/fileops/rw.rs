// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::{KError, KResult};
use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;

use super::super::controller_state::ControllerState;
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
) -> KResult<(u64, u64)> {
    rpc_writeat(rpc_client, pid, fd, -1, data)
}

pub(crate) fn rpc_writeat(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    offset: i64,
    data: &[u8],
) -> KResult<(u64, u64)> {
    debug!("Write({:?}, {:?})", fd, offset);

    // Constrcut request data
    let req = RWReq {
        pid,
        fd,
        len: data.len() as u64,
        offset,
    };
    let mut req_data = [0u8; core::mem::size_of::<RWReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode write request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call readat() or read() RPCs
    let rpc_type = if offset == -1 {
        KernelRpc::Write as RPCType
    } else {
        KernelRpc::WriteAt as RPCType
    };
    rpc_client.call(rpc_type, &[&req_data, &data], &mut [&mut res_data])?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        debug!("Write() {:?}", res);
        return *res;
    } else {
        return Err(KError::from(RPCError::MalformedResponse));
    }
}

// This function is just a wrapper for rpc_readat
pub(crate) fn rpc_read(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    buff_ptr: &mut [u8],
) -> KResult<(u64, u64)> {
    rpc_readat(rpc_client, pid, fd, buff_ptr, -1)
}

pub(crate) fn rpc_readat(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    fd: FileDescriptor,
    buff_ptr: &mut [u8],
    offset: i64,
) -> KResult<(u64, u64)> {
    debug!("Read({:?}, {:?})", buff_ptr.len(), offset);

    // Construct request data
    let req = RWReq {
        pid,
        fd,
        len: buff_ptr.len() as u64,
        offset,
    };
    let mut req_data = [0u8; core::mem::size_of::<RWReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.expect("Failed to encode read request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];

    // Call Read() or ReadAt() RPC
    let rpc_type = if offset == -1 {
        KernelRpc::Read as RPCType
    } else {
        KernelRpc::ReadAt as RPCType
    };
    rpc_client.call(
        KernelRpc::ReadAt as RPCType,
        &[&req_data],
        &mut [&mut res_data, buff_ptr],
    )?;

    // Decode result, if successful, return result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            debug!("Read(At)() {:?}", res);
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for read() RPCs in the controller
pub(crate) fn handle_read(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
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
        construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
        return Ok(state);
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
    construct_ret_extra_data(hdr, payload, ret, additional_data as u64);
    Ok(state)
}

// RPC Handler function for write() RPCs in the controller
pub(crate) fn handle_write(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    // Decode request
    let ret = if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
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

        match (remaining[..req.len as usize]).try_into() {
            Ok(data) => cnrfs::MlnrKernelNode::file_write(req.pid, req.fd, data, offset),
            Err(e) => Err(e),
        }
    // Return error if failed to decode request
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        Err(KError::from(RPCError::MalformedRequest))
    };
    construct_ret(hdr, payload, ret);
    Ok(state)
}
