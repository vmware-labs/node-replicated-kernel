// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{unsafe_abomonate, Abomonation};
use core::{convert::TryInto, str::Utf8Error};
use core2::io::Result as IOResult;
use core2::io::Write;

/// Node ID for servers/clients
pub type ClientId = u64;

#[derive(Debug)]
pub(crate) struct ClientIdRes {
    pub client_id: ClientId,
}
unsafe_abomonate!(ClientIdRes: client_id);

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
pub enum RPCError {
    // RPC
    MissingData,
    ExtraData,
    TransportError,
    MalformedResponse,
    MalformedRequest,
    InternalError,
    DuplicateRPCType,

    // File IO
    InvalidFile,
    InvalidFlags,
    InvalidOffset,
    PermissionError,
    AlreadyPresent,
    DirectoryError,
    OpenFileLimit,
    FileDescForPidAlreadyAdded,
    NoFileDescForPid,

    // Syscall Errors
    InvalidSyscallArgument1 {
        a: u64,
    },
    InvalidVSpaceOperation {
        a: u64,
    },
    InvalidProcessOperation {
        a: u64,
    },
    InvalidSystemOperation {
        a: u64,
    },

    // General Errors
    BadAddress,
    NotSupported,

    /// Can't convert some arg to string
    Utf8Error,
    /// Out of memory during request
    OutOfMemory,
}
unsafe_abomonate!(RPCError);

impl core::convert::From<Utf8Error> for RPCError {
    fn from(_e: Utf8Error) -> Self {
        RPCError::Utf8Error
    }
}

impl core::convert::From<alloc::collections::TryReserveError> for RPCError {
    fn from(_: alloc::collections::TryReserveError) -> Self {
        RPCError::OutOfMemory
    }
}

pub type RPCType = u8;
pub const RPC_TYPE_CONNECT: u8 = 0u8;

#[derive(Debug, Default)]
#[repr(C)]
pub struct RPCHeader {
    pub client_id: u64,
    pub pid: usize,
    pub req_id: u64,
    pub msg_type: RPCType,
    pub msg_len: u64,
}

pub const HDR_LEN: usize = core::mem::size_of::<RPCHeader>();

impl RPCHeader {
    /// # Safety
    /// - `self` must be valid RPCHeader
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; HDR_LEN] {
        ::core::slice::from_raw_parts_mut((self as *const RPCHeader) as *mut u8, HDR_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid RPCHeader
    pub unsafe fn as_bytes(&self) -> &[u8; HDR_LEN] {
        ::core::slice::from_raw_parts((self as *const RPCHeader) as *const u8, HDR_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }
}

pub const MAX_BUFF_LEN: usize = 8192;

#[repr(C)]
pub struct MBuf {
    pub hdr: RPCHeader,
    pub data: [u8; MAX_BUFF_LEN - HDR_LEN],
}

impl Default for MBuf {
    fn default() -> Self {
        MBuf {
            hdr: RPCHeader::default(),
            data: [0; MAX_BUFF_LEN - HDR_LEN],
        }
    }
}

impl MBuf {
    /// # Safety
    /// - `self` must be valid RPCHeader
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; MAX_BUFF_LEN] {
        ::core::slice::from_raw_parts_mut((self as *const MBuf) as *mut u8, MAX_BUFF_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid RPCHeader
    pub unsafe fn as_bytes(&self) -> &[u8; MAX_BUFF_LEN] {
        ::core::slice::from_raw_parts((self as *const MBuf) as *const u8, MAX_BUFF_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }
}
