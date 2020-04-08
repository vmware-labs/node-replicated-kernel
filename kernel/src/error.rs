use custom_error::custom_error;

use alloc::string::String;
use alloc::string::ToString;

use kpi::SystemCallError;

custom_error! {
    #[derive(PartialEq, Clone)]
    pub KError
    ProcessNotSet = "CURRENT_PROCESS is not set",
    ReplicaNotSet = "Replica is not set-up in the KCB",
    NotSupported = "Request is not yet supported",
    CoreAlreadyAllocated = "The requested core is already allocated by another process.",
    InvalidSyscallArgument1{a: u64} = "Invalid 1st syscall argument supplied: {}",
    InvalidVSpaceOperation{a: u64} = "Invalid VSpace Operation (2nd syscall argument) supplied: {}",
    InvalidProcessOperation{a: u64} = "Invalid Process Operation (2nd syscall argument) supplied: {}",
    ProcessCreate{desc: String}  = "Unable to create process: {desc}",
    VSpace{source: crate::memory::vspace::AddressSpaceError} = "VSpace operation covers existing mapping",
    PhysicalMemory{source: crate::memory::AllocationError} = "Memory allocation failed",
    BadAddress = "Userspace pointer is not usable",
    FileSystem{source: crate::fs::FileSystemError} = "FileSystem operation does file based io",
    ProcessError{source: crate::process::ProcessError} = "Process Operation failed",
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
            KError::ProcessCreate { .. } => SystemCallError::InternalError,
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
