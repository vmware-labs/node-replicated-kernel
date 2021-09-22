// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::Abomonation;
use alloc::string::String;
use alloc::vec::Vec;

use crate::rpc::*;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub enum FileIO {
    /// TODO: remove this
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
    return op == FileIO::Create as RPCType
        || op == FileIO::Open as RPCType
        || op == FileIO::Read as RPCType
        || op == FileIO::ReadAt as RPCType
        || op == FileIO::Write as RPCType
        || op == FileIO::WriteAt as RPCType
        || op == FileIO::Close as RPCType
        || op == FileIO::GetInfo as RPCType
        || op == FileIO::Delete as RPCType
        || op == FileIO::WriteDirect as RPCType
        || op == FileIO::FileRename as RPCType
        || op == FileIO::MkDir as RPCType;
}

impl From<RPCType> for FileIO {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: RPCType) -> FileIO {
        match op {
            // 2 => FileIO::Create,
            3 => FileIO::Open,
            4 => FileIO::Read,
            5 => FileIO::ReadAt,
            6 => FileIO::Write,
            7 => FileIO::WriteAt,
            8 => FileIO::Close,
            9 => FileIO::GetInfo,
            10 => FileIO::Delete,
            11 => FileIO::WriteDirect,
            12 => FileIO::FileRename,
            13 => FileIO::MkDir,
            _ => FileIO::Unknown,
        }
    }
}
unsafe_abomonate!(FileIO);

#[derive(Debug)]
pub struct OpenReq {
    pub pathname: String,
    pub flags: u64,
    pub modes: u64,
}
unsafe_abomonate!(OpenReq: pathname, flags, modes);

#[derive(Debug)]
pub struct CloseReq {
    pub fd: u64,
}
unsafe_abomonate!(CloseReq: fd);

#[derive(Debug)]
pub struct DeleteReq {
    pub pathname: String,
}
unsafe_abomonate!(DeleteReq: pathname);

#[derive(Debug)]
pub struct RenameReq {
    pub oldname: String,
    pub newname: String,
}
unsafe_abomonate!(RenameReq: oldname, newname);

#[derive(Debug)]
pub struct RWReq {
    pub fd: u64,
    pub len: u64,
    pub offset: i64,
}
unsafe_abomonate!(RWReq: fd, len, offset);

#[derive(Debug)]
pub struct MkDirReq {
    pub pathname: String,
    pub modes: u64,
}
unsafe_abomonate!(MkDirReq: pathname, modes);

#[derive(Debug)]
pub struct GetInfoReq {
    pub name: String,
}
unsafe_abomonate!(GetInfoReq: name);

#[derive(Debug)]
pub struct FIORes {
    pub ret: Result<(u64, u64), RPCError>,
}
unsafe_abomonate!(FIORes: ret);
