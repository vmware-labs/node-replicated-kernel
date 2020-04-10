//! Defines the public kernel interface (i.e., system call interface)
//! and associated data-types.
#![no_std]
#![feature(asm)]

#[allow(non_snake_case)]
#[cfg(target_os = "bespin")]
extern crate alloc;

pub mod io;
pub mod process;
pub mod system;
pub mod upcall;
pub mod x86_64;

/// The syscall layer (only relevant for Ring3 code -> target_os = bespin)
#[cfg(target_os = "bespin")]
pub mod syscalls;

/// A short-cut to the architecture specific part that this crate was compiled for.
pub mod arch {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::*;
}

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
            _ => ProcessOperation::Unknown,
        }
    }
}

/// Flags for the map system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum VSpaceOperation {
    /// Map some anonymous memory
    Map = 1,
    /// Unmap a mapped region
    Unmap = 2,
    /// Identity map some device memory
    MapDevice = 3,
    /// Resolve a virtual to a physical address
    Identify = 4,
    Unknown,
}

impl From<u64> for VSpaceOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    fn from(op: u64) -> VSpaceOperation {
        match op {
            1 => VSpaceOperation::Map,
            2 => VSpaceOperation::Unmap,
            3 => VSpaceOperation::MapDevice,
            4 => VSpaceOperation::Identify,
            _ => VSpaceOperation::Unknown,
        }
    }
}

impl From<&str> for VSpaceOperation {
    /// Construct a VSpaceOperation enum based on a str.
    fn from(op: &str) -> VSpaceOperation {
        match op {
            "Map" => VSpaceOperation::Map,
            "Unmap" => VSpaceOperation::Unmap,
            "MapDevice" => VSpaceOperation::MapDevice,
            "Identify" => VSpaceOperation::Identify,
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
    Unknown,
}

impl From<u64> for SystemOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    fn from(op: u64) -> SystemOperation {
        match op {
            1 => SystemOperation::GetHardwareThreads,
            _ => SystemOperation::Unknown,
        }
    }
}

impl From<&str> for SystemOperation {
    /// Construct a SystemOperation enum based on a str.
    fn from(op: &str) -> SystemOperation {
        match op {
            "GetHardwareThreads" => SystemOperation::GetHardwareThreads,
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
            5 => SystemCall::FileIO,
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
