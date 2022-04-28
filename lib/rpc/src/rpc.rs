// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::Abomonation;
use core::{cell::UnsafeCell, convert::TryInto};

/// Node ID for servers/clients
pub type NodeId = u64;

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
    InvalidSyscallArgument1 { a: u64 },
    InvalidVSpaceOperation { a: u64 },
    InvalidProcessOperation { a: u64 },
    InvalidSystemOperation { a: u64 },

    // General Errors
    BadAddress,
    NotSupported,
}
unsafe_abomonate!(RPCError);

pub type RPCType = u8;

#[derive(Debug, Default)]
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
pub type PacketBuffer = [u8; MAX_BUFF_LEN];

#[repr(transparent)]
pub struct MBuf(pub UnsafeCell<PacketBuffer>);

impl Default for MBuf {
    fn default() -> Self {
        MBuf(UnsafeCell::new([0; MAX_BUFF_LEN]))
    }
}

impl MBuf {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*(self.0.get() as *const [u8]) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn as_mut_bytes(&self) -> &mut [u8] {
        unsafe { &mut *(self.0.get() as *mut [u8]) }
    }

    pub fn get_hdr(&self) -> &RPCHeader {
        unsafe { &*(self.0.get() as *const RPCHeader) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get_hdr_mut(&self) -> &mut RPCHeader {
        unsafe { &mut *(self.0.get() as *mut RPCHeader) }
    }

    pub fn get_data(&self) -> &[u8] {
        unsafe { &*(self.0.get().add(HDR_LEN) as *const [u8]) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get_data_mut(&self) -> &mut [u8] {
        unsafe { &mut *(self.0.get().add(HDR_LEN) as *mut [u8]) }
    }
}
