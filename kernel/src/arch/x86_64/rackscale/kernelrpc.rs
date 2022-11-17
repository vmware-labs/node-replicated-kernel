// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryFrom;

use abomonation::{encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error};

use rpc::rpc::*;

use crate::error::KError;
use crate::fs::{cnrfs, NrLock};
use crate::nr;
use crate::process::Pid;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub(crate) enum KernelRpc {
    /// Create a file
    Create = 0,
    /// Open a file
    Open = 1,
    /// Read from a file
    Read = 2,
    /// Read from a file from the given offset
    ReadAt = 3,
    /// Write to a file
    Write = 4,
    /// Write to a file
    WriteAt = 5,
    /// Close an opened file.
    Close = 6,
    /// Get the information related to the file.
    GetInfo = 7,
    /// Delete the file
    Delete = 8,
    /// Write to a file without going into NR.
    WriteDirect = 9,
    /// Rename a file.
    FileRename = 10,
    /// Create a directory.
    MkDir = 11,

    /// Log (print) message of a process.
    Log = 12,
    /// Allocate physical memory for a process.
    AllocatePhysical = 13,
    /// Release physical memory from a process.
    ReleasePhysical = 14,
    /// Allocate a core for a process
    RequestCore = 15,

    /// Request work (e.g., request cores) - used by client to ask controller for tasks
    RequestWork = 16,

    /// Get the hardware threads for the rack
    GetHardwareThreads = 17,
}

impl TryFrom<RPCType> for KernelRpc {
    type Error = KError;

    /// Construct a RPCType enum based on a 8-bit value.
    fn try_from(op: RPCType) -> Result<Self, Self::Error> {
        match op {
            0 => Ok(KernelRpc::Create),
            1 => Ok(KernelRpc::Open),
            2 => Ok(KernelRpc::Read),
            3 => Ok(KernelRpc::ReadAt),
            4 => Ok(KernelRpc::Write),
            5 => Ok(KernelRpc::WriteAt),
            6 => Ok(KernelRpc::Close),
            7 => Ok(KernelRpc::GetInfo),
            8 => Ok(KernelRpc::Delete),
            9 => Ok(KernelRpc::WriteDirect),
            10 => Ok(KernelRpc::FileRename),
            11 => Ok(KernelRpc::MkDir),
            12 => Ok(KernelRpc::Log),
            13 => Ok(KernelRpc::AllocatePhysical),
            15 => Ok(KernelRpc::ReleasePhysical),
            15 => Ok(KernelRpc::RequestCore),
            16 => Ok(KernelRpc::RequestWork),
            17 => Ok(KernelRpc::GetHardwareThreads),
            _ => Err(KError::InvalidRpcType),
        }
    }
}
unsafe_abomonate!(KernelRpc);

// Struct used to encapulate a system call result
#[derive(Debug)]
pub(crate) struct KernelRpcRes {
    pub ret: Result<(u64, u64), RPCError>,
}
unsafe_abomonate!(KernelRpcRes: ret);
pub(crate) const KernelRpcRes_SIZE: u64 = core::mem::size_of::<KernelRpcRes>() as u64;

// Below are utility functions for working with KernelRpcRes

#[inline(always)]
pub(crate) fn construct_error_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    err: RPCError,
) -> Result<(), RPCError> {
    let res = KernelRpcRes { ret: Err(err) };
    construct_ret(hdr, payload, res)
}

#[inline(always)]
pub(crate) fn construct_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    res: KernelRpcRes,
) -> Result<(), RPCError> {
    construct_ret_extra_data(hdr, payload, res, 0)
}

#[inline(always)]
pub(crate) fn construct_ret_extra_data(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    res: KernelRpcRes,
    additional_data_len: u64,
) -> Result<(), RPCError> {
    // Encode payload in buffer
    unsafe { encode(&res, &mut payload) }.unwrap();

    // Modify header and write into output buffer
    hdr.msg_len = KernelRpcRes_SIZE + additional_data_len;
    Ok(())
}

#[inline(always)]
pub(crate) fn convert_return(
    cnrfs_ret: Result<(u64, u64), KError>,
) -> Result<(u64, u64), RPCError> {
    match cnrfs_ret {
        Ok(ret) => Ok(ret),
        Err(err) => Err(err.into()),
    }
}
