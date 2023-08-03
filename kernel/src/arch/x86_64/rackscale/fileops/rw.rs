// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::boxed::Box;
use core::borrow::{Borrow, BorrowMut};
use core::cell::RefCell;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use spin::Once;

use kpi::FileOperation;
use rpc::rpc::*;

use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use super::FileIO;
use crate::arch::process::Ring3Process;
use crate::error::{KError, KResult};
use crate::fs::cnrfs;
use crate::fs::fd::FileDescriptor;
use crate::nrproc::NrProcess;
use crate::process::{SliceAccess, UserSlice};

pub(crate) const RW_SHMEM_BUF_LEN: usize = 8192;

#[thread_local]
pub(crate) static RW_SHMEM_BUF: Once<RefCell<Box<[u8]>>> = Once::new();

#[derive(Debug)]
pub(crate) struct RWReq {
    pub pid: usize,
    pub fd: FileDescriptor,
    pub shared_buf_ptr: u64,
    pub len: u64,
    pub offset: i64,
}
unsafe_abomonate!(RWReq: pid, fd, len, offset);

pub(crate) fn rpc_write(pid: usize, fd: FileDescriptor, data: &[u8]) -> KResult<(u64, u64)> {
    rpc_writeat(pid, fd, -1, data)
}

pub(crate) fn rpc_writeat(
    pid: usize,
    fd: FileDescriptor,
    offset: i64,
    data: &[u8],
) -> KResult<(u64, u64)> {
    log::debug!("Write({:?}, {:?})", fd, offset);

    // Constrcut request data
    let req = RWReq {
        pid,
        fd,
        shared_buf_ptr: 0u64,
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
    CLIENT_STATE
        .rpc_client
        .lock()
        .call(rpc_type, &[&req_data, &data], &mut [&mut res_data])?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        log::debug!("Write() {:?}", res);
        return *res;
    } else {
        return Err(KError::from(RPCError::MalformedResponse));
    }
}

// This function is just a wrapper for rpc_readat
pub(crate) fn rpc_read(pid: usize, fd: FileDescriptor, uslice: UserSlice) -> KResult<(u64, u64)> {
    rpc_readat(pid, fd, uslice, -1)
}

pub(crate) fn rpc_readat(
    pid: usize,
    fd: FileDescriptor,
    uslice: UserSlice,
    offset: i64,
) -> KResult<(u64, u64)> {
    let uslice_len = uslice.len();
    log::debug!("Read({:?}, {:?})", uslice_len, offset);
    assert!(
        uslice_len <= RW_SHMEM_BUF_LEN,
        "Read too long - not supported!"
    );

    // Construct request data
    let req = RWReq {
        pid,
        fd,
        len: uslice.len() as u64,
        shared_buf_ptr: RW_SHMEM_BUF
            .get()
            .expect("read/write shmem buff should be initialized")
            .borrow_mut()
            .as_mut_ptr() as u64,
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

    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::ReadAt as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode result, if successful, return result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            Err(KError::from(RPCError::ExtraData))
        } else {
            let ret = *res;
            // Copy the read data into the user slice
            match ret {
                Ok((bytes_read, n)) => {
                    let my_ret = NrProcess::<Ring3Process>::userspace_exec_slice_mut(
                        uslice,
                        Box::try_new(move |ubuf: &mut [u8]| {
                            (&mut ubuf[..bytes_read as usize]).copy_from_slice(
                                &RW_SHMEM_BUF
                                    .get()
                                    .expect("read/write shmem buff should be initialized")
                                    .borrow()[..bytes_read as usize],
                            );
                            Ok((bytes_read, n))
                        })?,
                    );
                    log::debug!("Read(At)() {:?}", my_ret);
                    my_ret
                }
                Err(e) => Err(e),
            }
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for read() RPCs in the controller
pub(crate) fn handle_read(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Extract data needed from the request
    let fd;
    let len;
    let pid;
    let mut shared_buf;
    let mut offset = -1;
    let mut operation = FileOperation::Read;
    if let Some((req, _)) = unsafe { decode::<RWReq>(payload) } {
        log::debug!(
            "Read(At)(fd={:?}, len={:?}, offset={:?}), pid={:?}, shared_buf={:?}",
            req.fd,
            req.len,
            req.offset,
            req.pid,
            req.shared_buf_ptr,
        );
        fd = req.fd;
        len = req.len;
        pid = req.pid;
        shared_buf = req.shared_buf_ptr as *mut _;
        if hdr.msg_type == KernelRpc::ReadAt as RPCType {
            offset = req.offset;
            operation = FileOperation::ReadAt;
        }
    } else {
        log::error!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
        return Ok(());
    }

    let ret = cnrfs::MlnrKernelNode::file_read(
        pid,
        fd,
        &mut unsafe { core::slice::from_raw_parts_mut(shared_buf, len as usize) },
        offset,
    );

    // Construct return
    construct_ret(hdr, payload, ret);
    Ok(())
}

// RPC Handler function for write() RPCs in the controller
pub(crate) fn handle_write(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode request
    let ret = if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
        log::debug!(
            "Write(At)(fd={:?}, len={:?}, offset={:?}), pid={:?}",
            req.fd,
            req.len,
            req.offset,
            req.pid
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
        log::error!("Invalid payload for request: {:?}", hdr);
        Err(KError::from(RPCError::MalformedRequest))
    };
    construct_ret(hdr, payload, ret);
    Ok(())
}
