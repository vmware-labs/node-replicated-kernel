// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::ToString;
use core::convert::From;

use custom_error::custom_error;

use kpi::SystemCallError;

custom_error! {
    #[derive(PartialEq, Clone)]
    pub KError
    ProcessNotSet = "The core has no current process set.",
    ReplicaNotSet = "Replica is not set-up in the KCB.",
    NoExecutorForCore = "The core we're looking up has no executor allocated to it.",
    NotSupported = "The requested operation is not supported/does not exist.",
    BadAddress = "User-space pointer is not valid.",
    GlobalMemoryNotSet = "Global memory is not yet available.",
    CoreAlreadyAllocated = "The requested core is already allocated by another process.",
    InvalidSyscallArgument1{a: u64} = "Invalid 1st syscall argument supplied: {}",
    InvalidVSpaceOperation{a: u64} = "Invalid VSpace Operation (2nd syscall argument) supplied: {}",
    InvalidProcessOperation{a: u64} = "Invalid Process Operation (2nd syscall argument) supplied: {}",
    InvalidSystemOperation{a: u64} = "Invalid System Operation (2nd syscall argument) supplied: {}",
    VSpace{source: crate::memory::vspace::AddressSpaceError} = "VSpace operation covers existing mapping",
    PhysicalMemory{source: crate::memory::AllocationError} = "Memory allocation failed",
    FileSystem{source: crate::fs::FileSystemError} = "FileSystem operation does file based io",
    ProcessError{source: crate::process::ProcessError} = "Process Operation failed",
    InvalidAffinityId = "Specified an invalid NUMA node ID for affinity.",
    OutOfPids = "Can't spawn more processes (out of Pids)",
    ProcessLoadingFailed = "Can't spawn more processes (out of Pids)",
    OutOfMemory = "Ran out of memory while performing an allocation",
    FileDescForPidAlreadyAdded = "PID is already stored in scheduler state",
    NoFileDescForPid = "No file-descriptors found for Pid",
}

impl From<fallible_collections::TryReserveError> for KError {
    fn from(_e: fallible_collections::TryReserveError) -> Self {
        KError::OutOfMemory
    }
}

impl From<hashbrown::TryReserveError> for KError {
    fn from(_e: hashbrown::TryReserveError) -> Self {
        KError::OutOfMemory
    }
}

impl From<core::alloc::AllocError> for KError {
    fn from(_e: core::alloc::AllocError) -> Self {
        KError::OutOfMemory
    }
}

impl Into<SystemCallError> for KError {
    /// Translate KErrors to SystemCallErrors.
    ///
    /// The idea is to reduce a big set of events into a smaller set of less precise errors.
    /// We can log the the precise errors before we return in the kernel since the conversion
    /// happens at the end of the system call.
    fn into(self) -> SystemCallError {
        match self {
            KError::VSpace { source: s } => s.into(),
            KError::InvalidSyscallArgument1 { .. } => SystemCallError::NotSupported,
            KError::InvalidVSpaceOperation { .. } => SystemCallError::NotSupported,
            KError::InvalidProcessOperation { .. } => SystemCallError::NotSupported,
            KError::BadAddress { .. } => SystemCallError::BadAddress,
            KError::FileSystem { source: s } => s.into(),
            _ => SystemCallError::InternalError,
        }
    }
}

impl Default for KError {
    fn default() -> KError {
        KError::NotSupported
    }
}
