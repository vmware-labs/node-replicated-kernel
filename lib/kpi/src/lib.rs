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

/// SystemCallStatus is an error code returned
/// by the kernel to the user-space caller.
///
/// It is passed back in the %rax register.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum SystemCallStatus {
    Ok = 0x0,
    NotSupported = 0x1,
}

/// Flags for the map system call
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum VSpaceOperation {
    Map = 1,
    Unmap = 2,
    Unknown,
}

impl VSpaceOperation {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(op: u64) -> VSpaceOperation {
        match op {
            1 => VSpaceOperation::Map,
            2 => VSpaceOperation::Unmap,
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
    Print = 1,
    Exit = 2,
    VSpace = 3,
    Io = 4,
    Unknown,
}

impl SystemCall {
    /// Construct a SystemCall enum based on a 64-bit value.
    pub fn new(handle: u64) -> SystemCall {
        match handle {
            1 => SystemCall::Print,
            2 => SystemCall::Exit,
            3 => SystemCall::VSpace,
            4 => SystemCall::Io,
            _ => SystemCall::Unknown,
        }
    }
}
