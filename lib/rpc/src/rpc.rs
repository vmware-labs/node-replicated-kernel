// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::Abomonation;
use alloc::string::String;
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

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub enum RPCType {
    /// Client requesting to register with RPC server
    Registration = 1,

    /// Create a file
    Create = 2,
    /// Open a file
    Open = 3,
    /// Read from a file
    Read = 4,
    /// Read from a file from the given offset
    ReadAt = 5,
    /// Write to a file
    Write = 6,
    /// Write to a file
    WriteAt = 7,
    /// Close an opened file.
    Close = 8,
    /// Get the information related to the file.
    GetInfo = 9,
    /// Delete the file
    Delete = 10,
    /// Write to a file without going into NR.
    WriteDirect = 11,
    /// Rename a file.
    FileRename = 12,
    /// Create a directory.
    MkDir = 13,
    Unknown,
}

pub fn is_fileio(op: RPCType) -> bool {
    return op == RPCType::Create
        || op == RPCType::Open
        || op == RPCType::Read
        || op == RPCType::ReadAt
        || op == RPCType::Write
        || op == RPCType::WriteAt
        || op == RPCType::Close
        || op == RPCType::GetInfo
        || op == RPCType::Delete
        || op == RPCType::WriteDirect
        || op == RPCType::FileRename
        || op == RPCType::MkDir;
}

impl From<u8> for RPCType {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: u8) -> RPCType {
        match op {
            1 => RPCType::Registration,

            // TODO: Add RPC requests
            // 2 => RPCType::Create,
            3 => RPCType::Open,
            4 => RPCType::Read,
            5 => RPCType::ReadAt,
            6 => RPCType::Write,
            7 => RPCType::WriteAt,
            8 => RPCType::Close,
            9 => RPCType::GetInfo,
            10 => RPCType::Delete,
            11 => RPCType::WriteDirect,
            12 => RPCType::FileRename,
            13 => RPCType::MkDir,

            _ => RPCType::Unknown,
        }
    }
}
unsafe_abomonate!(RPCType);

#[derive(Debug, Clone, Copy)]
pub struct RPCHeader {
    pub client_id: u64,
    pub pid: usize,
    pub req_id: u64,
    pub msg_type: RPCType,
    pub msg_len: u64,
}
unsafe_abomonate!(RPCHeader: client_id, pid, req_id, msg_type, msg_len);

//////// FILEIO Operations
#[derive(Debug)]
pub struct RPCOpenReq {
    pub pathname: String,
    pub flags: u64,
    pub modes: u64,
}
unsafe_abomonate!(RPCOpenReq: pathname, flags, modes);

#[derive(Debug)]
pub struct RPCCloseReq {
    pub fd: u64,
}
unsafe_abomonate!(RPCCloseReq: fd);

#[derive(Debug)]
pub struct RPCDeleteReq {
    pub pathname: String,
}
unsafe_abomonate!(RPCDeleteReq: pathname);

#[derive(Debug)]
pub struct RPCRenameReq {
    pub oldname: String,
    pub newname: String,
}
unsafe_abomonate!(RPCRenameReq: oldname, newname);

#[derive(Debug)]
pub struct RPCRWReq {
    pub fd: u64,
    pub len: u64,
    pub offset: i64,
}
unsafe_abomonate!(RPCRWReq: fd, len, offset);

#[derive(Debug)]
pub struct RPCMkDirReq {
    pub pathname: String,
    pub modes: u64,
}
unsafe_abomonate!(RPCMkDirReq: pathname, modes);

#[derive(Debug)]
pub struct RPCGetInfoReq {
    pub name: String,
}
unsafe_abomonate!(RPCGetInfoReq: name);

#[derive(Debug)]
pub struct RPCMkDirReq {
    pub pathname: Vec<u8>,
    pub modes: u64,
}
unsafe_abomonate!(RPCMkDirReq: pathname, modes);

#[derive(Debug)]
pub struct RPCGetInfoReq {
    pub name: Vec<u8>,
}
unsafe_abomonate!(RPCGetInfoReq: name);

#[derive(Debug)]
pub struct FIORPCRes {
    pub ret: Result<(u64, u64), RPCError>,
}
unsafe_abomonate!(FIORPCRes: ret);
//////// End FILEIO Operations
