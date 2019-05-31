//! Defines the public kernel interface (i.e., system call interface)
//! and associated data-types.
//!
//! # Note
//!
//! We follow the Linux system call register conventions which
//! uses %rax as it's first argument, for convenience this is ignored
//! (therefore set to 0 in all our syscall! invocations). We do
//! the dispatching in rust code which uses %rdi as it's first
//! argument.
#![no_std]

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
            _ => SystemCallError::Unknown,
        }
    }
}

/// Flags for the process system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum ProcessOperation {
    Exit = 1,
    Log = 2,
    Unknown,
}

impl From<u64> for ProcessOperation {
    /// Construct a ProcessOperation enum based on a 64-bit value.
    fn from(op: u64) -> ProcessOperation {
        match op {
            1 => ProcessOperation::Exit,
            2 => ProcessOperation::Log,
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

/// SystemCall is the type of call we are invoking.
///
/// It is passed to the kernel in the %rdi register.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum SystemCall {
    Process = 1,
    VSpace = 3,
    Unknown,
}

impl SystemCall {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(domain: u64) -> SystemCall {
        match domain {
            1 => SystemCall::Process,
            3 => SystemCall::VSpace,
            _ => SystemCall::Unknown,
        }
    }
}
