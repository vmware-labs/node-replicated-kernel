// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryFrom;

use abomonation::{encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use rpc::rpc::*;

use crate::error::{KError, KResult};

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
    /// Release a core from a process.
    ReleaseCore = 16,

    /// Get the hardware threads for the rack
    GetHardwareThreads = 17,

    /// send process logs reference to client
    GetShmemStructure = 18,

    /// request shmem frames
    GetShmemFrames = 19,
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
            14 => Ok(KernelRpc::ReleasePhysical),
            15 => Ok(KernelRpc::RequestCore),
            16 => Ok(KernelRpc::ReleaseCore),
            17 => Ok(KernelRpc::GetHardwareThreads),
            18 => Ok(KernelRpc::GetShmemStructure),
            19 => Ok(KernelRpc::GetShmemFrames),
            _ => Err(KError::InvalidRpcType),
        }
    }
}

pub(crate) const KernelRpcRes_SIZE: u16 = core::mem::size_of::<KResult<(u64, u64)>>() as MsgLen;

#[inline(always)]
pub(crate) fn construct_error_ret(hdr: &mut RPCHeader, payload: &mut [u8], err: KError) {
    construct_ret(hdr, payload, Err(err))
}

#[inline(always)]
pub(crate) fn construct_ret(hdr: &mut RPCHeader, payload: &mut [u8], res: KResult<(u64, u64)>) {
    construct_ret_extra_data(hdr, payload, res, 0)
}

#[inline(always)]
pub(crate) fn construct_ret_extra_data(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    res: KResult<(u64, u64)>,
    additional_data_len: u64,
) {
    // Encode payload in buffer
    unsafe { encode(&res, &mut payload) }.unwrap();

    // Modify header and write into output buffer
    hdr.msg_len = KernelRpcRes_SIZE + additional_data_len as MsgLen;
}
