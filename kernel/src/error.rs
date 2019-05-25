use core::fmt::{Debug, Display};
use custom_error::custom_error;

use alloc::string::String;
use alloc::string::ToString;

use kpi::SystemCallError;

custom_error! {pub KError
    ProcessNotSet = "CURRENT_PROCESS is not set",
    NotSupported = "Request is not yet supported",
    InvalidSyscallArgument1{a: u64} = "Invalid 1st syscall argument supplied: {}",
    InvalidVSpaceOperation{a: u64} = "Invalid VSpace Operation (2nd syscall argument) supplied: {}",
    InvalidProcessOperation{a: u64} = "Invalid Process Operation (2nd syscall argument) supplied: {}",
    ProcessCreate{desc: String}  = "Unable to create process: {desc}",
    VSpace{source: crate::arch::vspace::VSpaceError} = "VSpace operation covers existing mapping",
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
            KError::InvalidSyscallArgument1 { a: _ } => SystemCallError::NotSupported,
            KError::InvalidVSpaceOperation { a: _ } => SystemCallError::NotSupported,
            KError::InvalidProcessOperation { a: _ } => SystemCallError::NotSupported,
            KError::ProcessCreate { desc: _ } => SystemCallError::InternalError,
            _ => SystemCallError::InternalError,
        }
    }
}

impl From<String> for KError {
    /// TODO: Hard-coded ProcessCreate due to elfloader errors.
    fn from(err: String) -> KError {
        KError::ProcessCreate { desc: err }
    }
}

impl From<&str> for KError {
    /// TODO: Hard-coded ProcessCreate due to elfloader errors.
    fn from(err: &str) -> KError {
        KError::ProcessCreate {
            desc: String::from(err),
        }
    }
}
