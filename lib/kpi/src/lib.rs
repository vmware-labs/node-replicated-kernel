// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Defines the public kernel interface (i.e., system call interface)
//! and associated data-types.
#![no_std]

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
    /// Request a new core for the process.
    ReleaseCore = 8,
    /// Allocate a physical memory page as a mem object to the process.
    AllocatePhysical = 9,
    /// Release a physical memory page from the process.
    ReleasePhysical = 10,
}

impl ProcessOperation {
    /// Construct a ProcessOperation enum based on a 64-bit value.
    pub fn new(op: u64) -> Option<Self> {
        match op {
            1 => Some(Self::Exit),
            2 => Some(Self::Log),
            3 => Some(Self::GetVCpuArea),
            4 => Some(Self::AllocateVector),
            5 => Some(Self::SubscribeEvent),
            6 => Some(Self::GetProcessInfo),
            7 => Some(Self::RequestCore),
            8 => Some(Self::ReleaseCore),
            9 => Some(Self::AllocatePhysical),
            10 => Some(Self::ReleasePhysical),
            _ => None,
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
}

impl VSpaceOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(op: u64) -> Option<Self> {
        match op {
            1 => Some(Self::MapMem),
            2 => Some(Self::UnmapMem),
            3 => Some(Self::MapDevice),
            4 => Some(Self::MapMemFrame),
            5 => Some(Self::Identify),
            6 => Some(Self::MapPMem),
            7 => Some(Self::UnmapPMem),
            _ => None,
        }
    }
}

/// Flags for the fs related system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum FileOperation {
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
    /// Rename a file.
    FileRename = 9,
    /// Create a directory.
    MkDir = 10,
}

impl FileOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(op: u64) -> Option<Self> {
        match op {
            1 => Some(Self::Open),
            2 => Some(Self::Read),
            3 => Some(Self::ReadAt),
            4 => Some(Self::Write),
            5 => Some(Self::WriteAt),
            6 => Some(Self::Close),
            7 => Some(Self::GetInfo),
            8 => Some(Self::Delete),
            9 => Some(Self::FileRename),
            10 => Some(Self::MkDir),
            _ => None,
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
}

impl SystemOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(op: u64) -> Option<Self> {
        match op {
            1 => Some(SystemOperation::GetHardwareThreads),
            2 => Some(SystemOperation::Stats),
            3 => Some(SystemOperation::GetCoreID),
            _ => None,
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
    Test = 5,
}

impl SystemCall {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(domain: u64) -> Option<Self> {
        match domain {
            1 => Some(SystemCall::System),
            2 => Some(SystemCall::Process),
            3 => Some(SystemCall::VSpace),
            4 => Some(SystemCall::FileIO),
            5 => Some(SystemCall::Test),
            _ => None,
        }
    }
}
