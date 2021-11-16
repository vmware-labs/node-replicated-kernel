// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, Abomonation};
use alloc::vec::Vec;
use core2::io::Result as IOResult;
use core2::io::Write;
use kpi::FileOperation;
use log::{debug, warn};

use rpc::rpc::*;
use rpc::rpc_api::RPCClientAPI;

use crate::arch::exokernel::fio::*;
use crate::cnrfs;

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

pub fn handle_read(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    debug!("Starting read: {:?}", payload.as_ptr());
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
    let mut msg_type = FileIO::ReadAt;
    if let Some((req, _)) = unsafe { decode::<RWReq>(payload) } {
        debug!(
            "Read(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
            req.fd, req.len, req.offset, local_pid
        );
        fd = req.fd;
        len = req.len;
        if hdr.msg_type == FileIO::Read as RPCType {
            offset = req.offset;
            msg_type = FileIO::Read;
        }
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
    }

    // Read directly into payload buffer, at offset after result field & header
    let ret = if msg_type == FileIO::Read {
        cnrfs::MlnrKernelNode::file_io(
            FileOperation::Read,
            local_pid,
            fd,
            payload[FIORES_SIZE as usize..].as_mut_ptr() as u64,
            len,
            -1,
        )
    } else {
        cnrfs::MlnrKernelNode::file_io(
            FileOperation::ReadAt,
            local_pid,
            fd,
            payload[FIORES_SIZE as usize..].as_mut_ptr() as u64,
            len,
            offset,
        )
    };
    debug!("After calling read: {:?}", payload);

    let mut additional_data = 0;
    if let Ok((bytes_read, _)) = ret {
        additional_data = bytes_read;
    }

    let res = FIORes {
        ret: convert_return(ret),
    };
    debug!("About to construct read ret: {:?}", payload.as_ptr());
    construct_ret_extra_data(hdr, payload, res, additional_data as u64)
}

pub fn handle_write(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    debug!("Starting write: {:?}", payload.as_ptr());
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
        debug!(
            "Write(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
            req.fd, req.len, req.offset, local_pid
        );

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

        let res = FIORes {
            ret: convert_return(ret),
        };
        debug!("About to construct write ret: {:?}", payload.as_ptr());
        construct_ret(hdr, payload, res)
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
