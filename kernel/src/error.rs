// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::From;
use core::fmt;

use arrayvec::CapacityError;
use kpi::SystemCallError;
use rpc::rpc::RPCError;

use crate::memory::VAddr;

#[derive(PartialEq, Clone, Debug)]
pub enum KError {
    // General error
    BadAddress,
    GlobalMemoryNotSet,
    CoreAlreadyAllocated,
    OutOfMemory,
    ReplicaNotSet,
    ProcessNotSet,
    NotSupported,
    OutOfPids,
    NoExecutorForCore,

    // Syscall errors
    InvalidSyscallArgument1 { a: u64 },
    InvalidVSpaceOperation { a: u64 },
    InvalidProcessOperation { a: u64 },
    InvalidSystemOperation { a: u64 },

    // Physical memory errors
    InvalidLayout,
    CacheExhausted,
    CacheFull,
    CantGrowFurther { count: usize },
    KcbUnavailable,
    ManagerAlreadyBorrowed,
    InvalidAffinityId,
    CapacityOverflow,

    // Process Errors
    ProcessLoadingFailed,
    ProcessCreate,
    NoProcessFoundForPid,
    UnableToLoad,
    UnableToParseElf,
    NoExecutorAllocated,
    ExecutorCacheExhausted,
    InvalidGlobalThreadId,
    ExecutorNoLongerValid,
    ExecutorAlreadyBorrowed,
    NotEnoughMemory,
    InvalidFrameId,
    TooManyProcesses,
    TooManyRegisteredFrames,
    InvalidFileDescriptor,
    BinaryNotFound { binary: &'static str },

    // Address space errors
    InvalidFrame,
    AlreadyMapped { base: VAddr },
    BaseOverflow { base: u64 },
    NotMapped,
    InvalidLength,
    InvalidBase,

    // File IO
    InvalidFile,
    InvalidFlags,
    InvalidOffset,
    PermissionError,
    AlreadyPresent,
    DirectoryError,
    OpenFileLimit,
    FileDescForPidAlreadyAdded,
    NoFileDescForPid,

    // Debugging
    DebuggerAlreadyAttached,
    DebuggerStmFailure,
    DebuggerUnableToReadRegister,
    DebuggerUnableToWriteRegister,
}

impl From<CapacityError<crate::memory::Frame>> for KError {
    fn from(_err: CapacityError<crate::memory::Frame>) -> Self {
        KError::CacheFull
    }
}

impl From<core::cell::BorrowMutError> for KError {
    fn from(_err: core::cell::BorrowMutError) -> Self {
        KError::ManagerAlreadyBorrowed
    }
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

impl From<elfloader::ElfLoaderErr> for KError {
    fn from(_e: elfloader::ElfLoaderErr) -> Self {
        KError::ProcessCreate
    }
}

impl From<core::alloc::AllocError> for KError {
    fn from(_e: core::alloc::AllocError) -> Self {
        KError::OutOfMemory
    }
}

impl From<slabmalloc::AllocationError> for KError {
    fn from(err: slabmalloc::AllocationError) -> KError {
        match err {
            slabmalloc::AllocationError::InvalidLayout => KError::InvalidLayout,
            // slabmalloc OOM just means we have to refill:
            slabmalloc::AllocationError::OutOfMemory => KError::CacheExhausted,
        }
    }
}

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

impl From<KError> for SystemCallError {
    /// Translate KErrors to SystemCallErrors.
    ///
    /// The idea is to reduce a big set of events into a smaller set of less precise errors.
    /// We can log the the precise errors before we return in the kernel since the conversion
    /// happens at the end of the system call.
    fn from(e: KError) -> SystemCallError {
        match e {
            KError::InvalidSyscallArgument1 { .. } => SystemCallError::NotSupported,
            KError::InvalidVSpaceOperation { .. } => SystemCallError::NotSupported,
            KError::InvalidProcessOperation { .. } => SystemCallError::NotSupported,
            KError::BadAddress { .. } => SystemCallError::BadAddress,
            _ => SystemCallError::InternalError,
        }
    }
}

impl Default for KError {
    fn default() -> KError {
        KError::NotSupported
    }
}

impl fmt::Display for KError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KError::ProcessNotSet => write!(f, "The core has no current process set."),
            KError::ReplicaNotSet => write!(f, "Replica is not set-up in the KCB."),
            KError::NoExecutorForCore => {
                write!(
                    f,
                    "The core we're looking up has no executor allocated to it."
                )
            }
            KError::NotSupported => write!(
                f,
                "The requested operation is not supported/does not exist."
            ),
            KError::BadAddress => write!(f, "User-space pointer is not valid."),
            KError::GlobalMemoryNotSet => write!(f, "Global memory is not yet available."),
            KError::CoreAlreadyAllocated => {
                write!(
                    f,
                    "The requested core is already allocated by another process."
                )
            }
            KError::InvalidSyscallArgument1 { a } => {
                write!(f, "Invalid 1st syscall argument supplied: {}", a)
            }
            KError::InvalidVSpaceOperation { a } => {
                write!(
                    f,
                    "Invalid VSpace Operation (2nd syscall argument) supplied: {}",
                    a
                )
            }
            KError::InvalidProcessOperation { a } => {
                write!(
                    f,
                    "Invalid Process Operation (2nd syscall argument) supplied: {}",
                    a
                )
            }
            KError::InvalidSystemOperation { a } => {
                write!(
                    f,
                    "Invalid System Operation (2nd syscall argument) supplied: {}",
                    a
                )
            }
            KError::InvalidAffinityId => {
                write!(f, "Specified an invalid NUMA node ID for affinity.")
            }
            KError::CapacityOverflow => write!(f, "Internal data-structure grew too big"),

            KError::OutOfPids => write!(f, "Can't spawn more processes (out of Pids)"),
            KError::ProcessLoadingFailed => write!(f, "Can't spawn more processes (out of Pids)"),
            KError::OutOfMemory => write!(f, "Ran out of memory while performing an allocation"),
            KError::FileDescForPidAlreadyAdded => {
                write!(f, "PID is already stored in scheduler state")
            }
            KError::NoFileDescForPid => write!(f, "No file-descriptors found for Pid"),

            KError::ProcessCreate  => write!(f, "Unable to create process"),
            KError::NoProcessFoundForPid => write!(f, "No process was associated with the given Pid."),
            KError::UnableToLoad => write!(f, "Couldn't load process, invalid ELF file?"),
            KError::UnableToParseElf => write!(f, "Couldn't parse ELF file, invalid?"),
            KError::NoExecutorAllocated => write!(f, "We never allocated executors for this affinity region and process (need to fill cache)."),
            KError::ExecutorCacheExhausted => write!(f, "The executor cache for given affinity is empty (need to refill)"),
            KError::InvalidGlobalThreadId => write!(f, "Specified an invalid core"),
            KError::ExecutorNoLongerValid => write!(f, "The excutor was removed from the current core."),
            KError::ExecutorAlreadyBorrowed => write!(f, "The executor on the core was already borrowed (that's a bug)."),
            KError::NotEnoughMemory => write!(f, "Unable to reserve memory for internal process data-structures."),
            KError::InvalidFrameId => write!(f, "The provided FrameId is not registered with the process"),
            KError::TooManyProcesses => write!(f, "Not enough space in process table (out of PIDs)."),
            KError::TooManyRegisteredFrames => write!(f, "Can't register more frames with the process (out of FIDs)."),
            KError::BinaryNotFound { binary } => write!(f, "Can't spawn binary {}: Not found", binary),

            KError::InvalidFrame => write!(f, "Supplied frame was invalid"),
            KError::AlreadyMapped{base} => write!(f, "Address space operation covers existing mapping {:?}", base),
            KError::BaseOverflow{base} => write!(f, "Provided virtual base {:#x} was invalid (led to overflow on mappings).", base),
            KError::NotMapped => write!(f, "The requested mapping was not found"),
            KError::InvalidLength => write!(f, "The supplied length was invalid"),
            KError::InvalidBase => write!(f, "The supplied base was invalid (alignment?)"),

            KError::InvalidLayout => write!(f, "Invalid layout for allocator provided."),
            KError::CacheExhausted => write!(f, "Couldn't allocate bytes on this cache, need to re-grow first."),
            KError::CacheFull => write!(f, "Cache can't hold any more objects."),
            KError::CantGrowFurther{count} => write!(f, "Cache full; only added {} elements.", count),
            KError::KcbUnavailable => write!(f, "KCB not set, memory allocation won't work at this point."),
            KError::ManagerAlreadyBorrowed => write!(f, "The memory manager was already borrowed (this is a bug)."),

            KError::InvalidFileDescriptor => write!(f, "Supplied file descriptor was invalid"),
            KError::InvalidFile => write!(f, "Supplied file was invalid"),
            KError::InvalidFlags => write!(f, "Supplied flags were invalid"),
            KError::InvalidOffset => write!(f, "Supplied offset was invalid"),
            KError::PermissionError => write!(f, "File/directory can't be read or written"),
            KError::AlreadyPresent => write!(f, "Fd/File already exists"),
            KError::DirectoryError => write!(f, "Can't read or write to a directory"),
            KError::OpenFileLimit => write!(f, "Maximum files are opened for a process"),

            KError::DebuggerAlreadyAttached => write!(f, "Debugger is already attached"),
            KError::DebuggerStmFailure => write!(f, "Failure while running the GDB state machine"),
            KError::DebuggerUnableToReadRegister => write!(f, "Can't read register"),
            KError::DebuggerUnableToWriteRegister => write!(f, "Can't write register"),

        }
    }
}
