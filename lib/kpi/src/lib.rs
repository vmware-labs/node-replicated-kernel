// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Defines the public kernel interface (i.e., system call interface)
//! and associated data-types.
#![no_std]
#![feature(
    llvm_asm,
    const_maybe_uninit_as_ptr,
    const_raw_ptr_deref,
    const_ptr_offset_from
)]

#[cfg(not(target_os = "none"))]
extern crate alloc;

#[macro_use]
extern crate abomonation;

pub mod io;
pub mod process;
pub mod system;
pub mod upcall;
pub mod x86_64;

/// The syscall layer (only relevant for Ring3 code -> target_os = nrk)
#[cfg(not(target_os = "none"))]
pub mod syscalls;

/// A short-cut to the architecture specific part that this crate was compiled for.
pub mod arch {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::*;
}

/// Start of the kernel address space.
pub const KERNEL_BASE: u64 = 0x4000_0000_0000;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
/// Errors returned by system calls.
pub enum SystemCallError {
    /// This means no error and should never be created.
    Ok = 0,
    /// Couldn't log the message (lost).
    NotLogged = 1,
    /// Requested Operation is not supported.
    NotSupported = 2,
    /// Can't overwrite exsting mapping in vspace.
    VSpaceAlreadyMapped = 3,
    /// Not enough memory available to fulfill operation.
    OutOfMemory = 4,
    /// Internal error that should not have happened.
    InternalError = 5,
    /// The userspace pointer can't be used for various reasons.
    BadAddress = 6,
    /// There is something wrong with the file descriptor.
    BadFileDescriptor = 7,
    /// The flags are incorrect to access the file.
    BadFlags = 8,
    /// Operation is not permitted.
    PermissionError = 9,
    /// Bad offset
    OffsetError = 10,
    /// Placeholder for an invalid, unknown error code.
    Unknown,
}

impl From<u64> for SystemCallError {
    /// Construct a `SystemCallError` enum based on a 64-bit value.
    fn from(e: u64) -> SystemCallError {
        match e {
            1 => SystemCallError::NotLogged,
            2 => SystemCallError::NotSupported,
            3 => SystemCallError::VSpaceAlreadyMapped,
            4 => SystemCallError::OutOfMemory,
            5 => SystemCallError::InternalError,
            6 => SystemCallError::BadAddress,
            7 => SystemCallError::BadFileDescriptor,
            8 => SystemCallError::BadFlags,
            9 => SystemCallError::PermissionError,
            10 => SystemCallError::OffsetError,
            _ => SystemCallError::Unknown,
        }
    }
}

/// Flags for the process system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum ProcessOperation {
    /// Exit the process.
    Exit = 1,
    /// Log to console.
    Log = 2,
    /// Sets the process control and save area for trap/IRQ forwarding
    /// to user-space for this process and CPU.
    GetVCpuArea = 3,
    /// Allocate a device interrupt vector.
    AllocateVector = 4,
    /// Subscribe to a trap and/or interrupt events.
    SubscribeEvent = 5,
    /// Query info about the current process.
    GetProcessInfo = 6,
    /// Request a new core for the process.
    RequestCore = 7,
    /// Allocate a physical memory page as a mem object to the process.
    AllocatePhysical = 8,
    Unknown,
}

impl From<u64> for ProcessOperation {
    /// Construct a ProcessOperation enum based on a 64-bit value.
    fn from(op: u64) -> ProcessOperation {
        match op {
            1 => ProcessOperation::Exit,
            2 => ProcessOperation::Log,
            3 => ProcessOperation::GetVCpuArea,
            4 => ProcessOperation::AllocateVector,
            5 => ProcessOperation::SubscribeEvent,
            6 => ProcessOperation::GetProcessInfo,
            7 => ProcessOperation::RequestCore,
            8 => ProcessOperation::AllocatePhysical,
            _ => ProcessOperation::Unknown,
        }
    }
}

impl From<&str> for ProcessOperation {
    /// Construct a ProcessOperation enum based on a str.
    fn from(op: &str) -> ProcessOperation {
        match op {
            "Exit" => ProcessOperation::Exit,
            "Log" => ProcessOperation::Log,
            "GetVCpuArea" => ProcessOperation::GetVCpuArea,
            "AllocateVector" => ProcessOperation::AllocateVector,
            "SubscribeEvent" => ProcessOperation::SubscribeEvent,
            "GetProcessInfo" => ProcessOperation::GetProcessInfo,
            "RequestCore" => ProcessOperation::RequestCore,
            "AllocatePhysical" => ProcessOperation::AllocatePhysical,
            _ => ProcessOperation::Unknown,
        }
    }
}

/// Flags to specify the memory type
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum MemType {
    /// The allocations will be done from DRAM.
    Mem = 1,
    /// The allocations will be done from PMEM.
    PMem = 2,
    Invalid,
}

/// Flags for the map system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum VSpaceOperation {
    /// Map some anonymous memory
    MapMem = 1,
    /// Unmap a mapped region
    UnmapMem = 2,
    /// Identity map some device memory
    MapDevice = 3,
    /// Map a previously allocated physical frame,
    MapMemFrame = 4,
    /// Resolve a virtual to a physical address
    Identify = 5,
    /// Map some anonymous memory from PMem
    MapPMem = 6,
    /// Unmap a PMem mapped region
    UnmapPMem = 7,
    Unknown,
}

impl From<u64> for VSpaceOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    fn from(op: u64) -> VSpaceOperation {
        match op {
            1 => VSpaceOperation::MapMem,
            2 => VSpaceOperation::UnmapMem,
            3 => VSpaceOperation::MapDevice,
            4 => VSpaceOperation::MapMemFrame,
            5 => VSpaceOperation::Identify,
            6 => VSpaceOperation::MapPMem,
            7 => VSpaceOperation::UnmapPMem,
            _ => VSpaceOperation::Unknown,
        }
    }
}

impl From<&str> for VSpaceOperation {
    /// Construct a VSpaceOperation enum based on a str.
    fn from(op: &str) -> VSpaceOperation {
        match op {
            "MapMem" => VSpaceOperation::MapMem,
            "UnmapMem" => VSpaceOperation::UnmapMem,
            "MapDevice" => VSpaceOperation::MapDevice,
            "MapMemFrame" => VSpaceOperation::MapMemFrame,
            "Identify" => VSpaceOperation::Identify,
            "MapPMem" => VSpaceOperation::MapPMem,
            "UnmapPMem" => VSpaceOperation::UnmapPMem,
            _ => VSpaceOperation::Unknown,
        }
    }
}

/// Flags for the fs related system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum FileOperation {
    /// Create a file
    Create = 1,
    /// Open a file
    Open = 2,
    /// Read from a file
    Read = 3,
    /// Read from a file from the given offset
    ReadAt = 4,
    /// Write to a file
    Write = 5,
    /// Write to a file
    WriteAt = 6,
    /// Close an opened file.
    Close = 7,
    /// Get the information related to the file.
    GetInfo = 8,
    /// Delete the file
    Delete = 9,
    /// Write to a file without going into NR.
    WriteDirect = 10,
    /// Rename a file.
    FileRename = 11,
    /// Create a directory.
    MkDir = 12,
    Unknown,
}

impl From<u64> for FileOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    fn from(op: u64) -> FileOperation {
        match op {
            1 => FileOperation::Create,
            2 => FileOperation::Open,
            3 => FileOperation::Read,
            4 => FileOperation::ReadAt,
            5 => FileOperation::Write,
            6 => FileOperation::WriteAt,
            7 => FileOperation::Close,
            8 => FileOperation::GetInfo,
            9 => FileOperation::Delete,
            10 => FileOperation::WriteDirect,
            11 => FileOperation::FileRename,
            12 => FileOperation::MkDir,
            _ => FileOperation::Unknown,
        }
    }
}

impl From<&str> for FileOperation {
    /// Construct a FileOperation enum based on a str.
    fn from(op: &str) -> FileOperation {
        match op {
            "Create" => FileOperation::Create,
            "Open" => FileOperation::Open,
            "Read" => FileOperation::Read,
            "ReadAt" => FileOperation::ReadAt,
            "Write" => FileOperation::Write,
            "WriteAt" => FileOperation::WriteAt,
            "Close" => FileOperation::Close,
            "GetInfo" => FileOperation::GetInfo,
            "Delete" => FileOperation::Delete,
            "WriteDirect" => FileOperation::WriteDirect,
            "Rename" => FileOperation::FileRename,
            "MkDir" => FileOperation::MkDir,
            _ => FileOperation::Unknown,
        }
    }
}

/// Operations that query/set system-wide information.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum SystemOperation {
    /// Query information about available hardware threads in the system
    GetHardwareThreads = 1,
    /// Print system/per-core info.
    Stats = 2,
    /// Get the core id for the current thread.
    GetCoreID = 3,
    Unknown,
}

impl From<u64> for SystemOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    fn from(op: u64) -> SystemOperation {
        match op {
            1 => SystemOperation::GetHardwareThreads,
            2 => SystemOperation::Stats,
            3 => SystemOperation::GetCoreID,
            _ => SystemOperation::Unknown,
        }
    }
}

impl From<&str> for SystemOperation {
    /// Construct a SystemOperation enum based on a str.
    fn from(op: &str) -> SystemOperation {
        match op {
            "GetHardwareThreads" => SystemOperation::GetHardwareThreads,
            "Stats" => SystemOperation::Stats,
            "GetCoreID" => SystemOperation::GetCoreID,
            _ => SystemOperation::Unknown,
        }
    }
}

/// SystemCall is the type of call we are invoking.
///
/// It is passed to the kernel in the %rdi register.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum SystemCall {
    System = 1,
    Process = 2,
    VSpace = 3,
    FileIO = 4,
    Unknown,
}

impl SystemCall {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(domain: u64) -> SystemCall {
        match domain {
            1 => SystemCall::System,
            2 => SystemCall::Process,
            3 => SystemCall::VSpace,
            4 => SystemCall::FileIO,
            _ => SystemCall::Unknown,
        }
    }
}

impl From<&str> for SystemCall {
    /// Construct a SystemCall enum based on a str.
    fn from(op: &str) -> SystemCall {
        match op {
            "System" => SystemCall::System,
            "Process" => SystemCall::Process,
            "VSpace" => SystemCall::VSpace,
            "FileIO" => SystemCall::FileIO,
            _ => SystemCall::Unknown,
        }
    }
}
