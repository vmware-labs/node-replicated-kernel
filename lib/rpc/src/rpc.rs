// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::Abomonation;
use alloc::vec::Vec;

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

#[derive(Debug, Clone, Copy)]
pub struct RPCHeader {
    pub client_id: u64,
    pub pid: usize,
    pub req_id: u64,
    pub msg_type: RPCType,
    pub msg_len: u64,
}
unsafe_abomonate!(RPCHeader: client_id, pid, req_id, msg_type, msg_len);
