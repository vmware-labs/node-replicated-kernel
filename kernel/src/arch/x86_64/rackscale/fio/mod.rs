// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{unsafe_abomonate, Abomonation};
use rpc::rpc::RPCType;

pub mod close;
pub mod delete;
pub mod getinfo;
pub mod mkdir;
pub mod open;
pub mod rename;
pub mod rw;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub(crate) enum FileIO {
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

    Unknown = 12,
}

impl From<RPCType> for FileIO {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: RPCType) -> FileIO {
        match op {
            0 => FileIO::Create,
            1 => FileIO::Open,
            2 => FileIO::Read,
            3 => FileIO::ReadAt,
            4 => FileIO::Write,
            5 => FileIO::WriteAt,
            6 => FileIO::Close,
            7 => FileIO::GetInfo,
            8 => FileIO::Delete,
            9 => FileIO::WriteDirect,
            10 => FileIO::FileRename,
            11 => FileIO::MkDir,
            _ => FileIO::Unknown,
        }
    }
}
unsafe_abomonate!(FileIO);
