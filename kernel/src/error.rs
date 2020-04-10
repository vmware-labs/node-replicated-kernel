use alloc::string::ToString;

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
    CoreAlreadyAllocated = "The requested core is already allocated by another process.",
    InvalidSyscallArgument1{a: u64} = "Invalid 1st syscall argument supplied: {}",
    InvalidVSpaceOperation{a: u64} = "Invalid VSpace Operation (2nd syscall argument) supplied: {}",
    InvalidProcessOperation{a: u64} = "Invalid Process Operation (2nd syscall argument) supplied: {}",
    InvalidSystemOperation{a: u64} = "Invalid System Operation (2nd syscall argument) supplied: {}",
    VSpace{source: crate::memory::vspace::AddressSpaceError} = "VSpace operation covers existing mapping",
    PhysicalMemory{source: crate::memory::AllocationError} = "Memory allocation failed",
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
