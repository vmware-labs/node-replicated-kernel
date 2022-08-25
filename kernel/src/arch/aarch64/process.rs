// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::process::Pid;

/// the architecture specific stack alignment for processes
pub(crate) const STACK_ALIGNMENT: usize = 16;

/// The process model of the current architecture.
pub(crate) type ArchProcess = Ring3Process;

///The executor of the current architecture.
pub(crate) type ArchExecutor = Ring3Executor;

/// A handle to the currently active (scheduled on the core) process.
#[thread_local]
pub(crate) static CURRENT_EXECUTOR: RefCell<Option<Box<ArchExecutor>>> = RefCell::new(None);

/// Swaps out current process with a new process. Returns the old process.
pub(crate) fn swap_current_executor(new_executor: Box<ArchExecutor>) -> Option<Box<ArchExecutor>> {
    CURRENT_EXECUTOR.borrow_mut().replace(new_executor)
}

pub(crate) fn has_executor() -> bool {
    CURRENT_EXECUTOR.borrow().is_some()
}

/// Spawns a new process
///
/// We're loading a process from a module:
/// - First we are constructing our own custom elfloader trait to load figure out
///   which program headers in the module will be writable (these should not be replicated by NR)
/// - Then we continue by creating a new Process through an nr call
/// - Then we allocate a bunch of memory on all NUMA nodes to create enough dispatchers
///   so we can run on all cores
/// - Finally we allocate a dispatcher to the current core (0) and start running the process
#[cfg(target_os = "none")]
pub(crate) fn spawn(binary: &'static str) -> Result<Pid, KError> {
    panic!("not yet implemented");
}
