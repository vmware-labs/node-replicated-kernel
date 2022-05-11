// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::From;

use rpc::rpc::RPCError;

use crate::error::KError;

impl From<KError> for RPCError {
    /// Translate KErrors to RPCErrors.
    fn from(e: KError) -> RPCError {
        match e {
            // File IO
            KError::InvalidFile => RPCError::InvalidFile,
            KError::InvalidFlags => RPCError::InvalidFlags,
            KError::InvalidOffset => RPCError::InvalidOffset,
            KError::PermissionError => RPCError::PermissionError,
            KError::AlreadyPresent => RPCError::AlreadyPresent,
            KError::DirectoryError => RPCError::DirectoryError,
            KError::OpenFileLimit => RPCError::OpenFileLimit,
            KError::FileDescForPidAlreadyAdded => RPCError::FileDescForPidAlreadyAdded,
            KError::NoFileDescForPid => RPCError::NoFileDescForPid,

            // Syscall errors
            KError::InvalidSyscallArgument1 { a } => RPCError::InvalidSyscallArgument1 { a },
            KError::InvalidVSpaceOperation { a } => RPCError::InvalidVSpaceOperation { a },
            KError::InvalidProcessOperation { a } => RPCError::InvalidProcessOperation { a },
            KError::InvalidSystemOperation { a } => RPCError::InvalidSystemOperation { a },

            // General Errors
            KError::BadAddress => RPCError::BadAddress,
            KError::NotSupported => RPCError::NotSupported,
            _ => RPCError::InternalError,
        }
    }
}

impl From<RPCError> for KError {
    /// Translate RPCErrors to KErrors.
    fn from(e: RPCError) -> KError {
        match e {
            // File IO
            RPCError::InvalidFile => KError::InvalidFile,
            RPCError::InvalidFlags => KError::InvalidFlags,
            RPCError::InvalidOffset => KError::InvalidOffset,
            RPCError::PermissionError => KError::PermissionError,
            RPCError::AlreadyPresent => KError::AlreadyPresent,
            RPCError::DirectoryError => KError::DirectoryError,
            RPCError::OpenFileLimit => KError::OpenFileLimit,
            RPCError::FileDescForPidAlreadyAdded => KError::FileDescForPidAlreadyAdded,
            RPCError::NoFileDescForPid => KError::NoFileDescForPid,

            // Syscall errors
            RPCError::InvalidSyscallArgument1 { a } => KError::InvalidSyscallArgument1 { a },
            RPCError::InvalidVSpaceOperation { a } => KError::InvalidVSpaceOperation { a },
            RPCError::InvalidProcessOperation { a } => KError::InvalidProcessOperation { a },
            RPCError::InvalidSystemOperation { a } => KError::InvalidSystemOperation { a },

            // General Errors
            RPCError::BadAddress => KError::BadAddress,
            RPCError::NotSupported => KError::NotSupported,
            // TODO: does this make sense as default? For RPCError::TransportError, etc?
            _ => KError::NotSupported,
        }
    }
}
