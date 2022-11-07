// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::collections::TryReserveError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::cell::RefCell;
use core::cmp::PartialEq;
use kpi::arch::SaveArea;
use lazy_static::lazy_static;

use crate::arch::kcb::per_core_mem;
use crate::error::KResult;
use crate::fs::{fd::FileDescriptorEntry, MAX_FILES_PER_PROCESS};
use crate::memory::detmem::DA;
use crate::memory::{Frame, VAddr};
use crate::nrproc::NrProcess;
use crate::prelude::KError;
use crate::process::{
    Eid, Executor, Pid, Process, ResumeHandle, MAX_FRAMES_PER_PROCESS, MAX_PROCESSES,
    MAX_WRITEABLE_SECTIONS_PER_PROCESS,
};
use kpi::process::{FrameId, ELF_OFFSET, EXECUTOR_OFFSET};
use node_replication::{Dispatch, Log, Replica};

use super::vspace::*;
use super::Module;
use super::MAX_NUMA_NODES;

use crate::memory::LARGE_PAGE_SIZE;

/// the architecture specific stack alignment for processes
pub(crate) const STACK_ALIGNMENT: usize = 16;

/// The process model of the current architecture.
pub(crate) type ArchProcess = EL0Process;

///The executor of the current architecture.
pub(crate) type ArchExecutor = EL0Executor;

///The resumer of the current architecture.
pub(crate) type ArchResumer = EL1Resumer;

pub(crate) struct EL0Process {
    /// EL0 Process ID.
    pub pid: Pid,
    /// Ring3Executor ID.
    pub current_eid: Eid,
    /// The address space of the process.
    pub vspace: VSpace,
    /// Offset where ELF is located.
    pub offset: VAddr,
    /// Process info struct (can be retrieved by user-space)
    pub pinfo: kpi::process::ProcessInfo,
    /// The entry point of the ELF file (set during elfloading).
    pub entry_point: VAddr,
    /// Executor cache (holds a per-region cache of executors)
    pub executor_cache: ArrayVec<Option<Vec<Box<ArchExecutor>>>, MAX_NUMA_NODES>,
    /// Offset where executor memory is located in user-space.
    pub executor_offset: VAddr,
    /// File descriptors for the opened file.
    pub fds: ArrayVec<Option<FileDescriptorEntry>, MAX_FILES_PER_PROCESS>,
    /// Physical frame objects registered to the process.
    pub frames: ArrayVec<Option<Frame>, MAX_FRAMES_PER_PROCESS>,
    /// Frames of the writeable ELF data section (shared across all replicated Process structs)
    pub writeable_sections: ArrayVec<Frame, MAX_WRITEABLE_SECTIONS_PER_PROCESS>,
    /// Section in ELF where last read-only header is
    ///
    /// (TODO(robustness): assumes that all read-only segments come before
    /// writable segments).
    pub read_only_offset: VAddr,
}

impl EL0Process {
    fn new(pid: Pid, da: DA) -> Result<Self, KError> {
        const NONE_EXECUTOR: Option<Vec<Box<ArchExecutor>>> = None;
        let executor_cache: ArrayVec<Option<Vec<Box<ArchExecutor>>>, MAX_NUMA_NODES> =
            ArrayVec::from([NONE_EXECUTOR; MAX_NUMA_NODES]);

        const NONE_FD: Option<FileDescriptorEntry> = None;
        let fds: ArrayVec<Option<FileDescriptorEntry>, MAX_FILES_PER_PROCESS> =
            ArrayVec::from([NONE_FD; MAX_FILES_PER_PROCESS]);

        let frames: ArrayVec<Option<Frame>, MAX_FRAMES_PER_PROCESS> =
            ArrayVec::from([None; MAX_FRAMES_PER_PROCESS]);

        Ok(Self {
            pid,
            current_eid: 0,
            offset: VAddr::from(ELF_OFFSET),
            vspace: VSpace::new(da)?,
            entry_point: VAddr::from(0usize),
            executor_cache,
            executor_offset: VAddr::from(EXECUTOR_OFFSET),
            fds,
            pinfo: Default::default(),
            frames,
            writeable_sections: ArrayVec::new(),
            read_only_offset: VAddr::zero(),
        })
    }
}

/// An executor is a thread running in a ring 3 in the context
/// (address-space) of a specific process.
///
/// # Notes
/// repr(C): Because `save_area` in is struct is written to from assembly
/// (and therefore should be first).
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct EL0Executor {
    /// CPU context save area (must be first, see exec.S).
    pub save_area: SaveArea,

    /// Allocated stack (base address).
    pub stack_base: VAddr,

    /// Up-call stack (base address).
    pub upcall_stack_base: VAddr,

    /// Process identifier
    pub pid: Pid,

    /// Executor Identifier
    pub eid: Eid,
}

impl EL0Executor {}

impl PartialEq<EL0Executor> for EL0Executor {
    fn eq(&self, other: &EL0Executor) -> bool {
        self.pid == other.pid && self.eid == other.eid
    }
}

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

pub(crate) fn current_pid() -> KResult<Pid> {
    Ok(CURRENT_EXECUTOR
        .borrow()
        .as_ref()
        .ok_or(KError::ProcessNotSet)?
        .pid)
}

lazy_static! {
    pub(crate) static ref PROCESS_TABLE: ArrayVec<ArrayVec<Arc<Replica<'static, NrProcess<ArchProcess>>>, MAX_PROCESSES>, MAX_NUMA_NODES> = {
        // Want at least one replica...
        let numa_nodes = core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes());
        let mut numa_cache = ArrayVec::new();
        for _n in 0..numa_nodes {
            let process_replicas = ArrayVec::new();
            debug_assert!(!numa_cache.is_full());
            numa_cache.push(process_replicas)
        }
        for pid in 0..MAX_PROCESSES {
                let log = Arc::try_new(Log::<<NrProcess<ArchProcess> as Dispatch>::WriteOperation>::new(
                    LARGE_PAGE_SIZE,
                )).expect("Can't initialize processes, out of memory.");

            let da = DA::new().expect("Can't initialize process deterministic memory allocator");
            for node in 0..numa_nodes {

                let pcm = per_core_mem();
                pcm.set_mem_affinity(node as atopology::NodeId).expect("Can't change affinity");
                debug_assert!(!numa_cache[node].is_full());
                let my_da = da.clone();
                let pr = ArchProcess::new(pid, my_da).expect("Can't create process during init");
                let p = Box::try_new(pr).expect("Not enough memory to initialize processes");
                let nrp = NrProcess::new(p, da.clone());
                numa_cache[node].push(Replica::<NrProcess<ArchProcess>>::with_data(&log, nrp));

                debug_assert_eq!(*crate::environment::NODE_ID, 0, "Expect initialization to happen on node 0.");
                pcm.set_mem_affinity(0 as atopology::NodeId).expect("Can't change affinity");
            }
        }

        numa_cache
    };
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

pub(crate) struct ArchProcessManagement;

impl crate::nrproc::ProcessManager for ArchProcessManagement {
    type Process = ArchProcess;

    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    > {
        &*super::process::PROCESS_TABLE
    }
}

/// Runs a closure `f` while the current core has access to user-space enabled.
///
/// Access is disabled again after `f` returns.
pub(crate) fn with_user_space_access_enabled<F, R>(f: F) -> KResult<R>
where
    F: FnOnce() -> KResult<R>,
{
    panic!("not yet implemented");
}

/// Resume the state saved in `SaveArea` using the `iretq` instruction.
///
/// # Safety
/// Pretty unsafe low-level API that switches to an arbitrary
/// context/instruction pointer. Caller should make sure that `state` is
/// "valid", meaning is an alive context that has not already been resumed.

pub(crate) struct EL1Resumer {
    pub save_area: *const SaveArea,
}

impl EL1Resumer {
    pub(crate) fn new_iret(save_area: *const SaveArea) -> EL1Resumer {
        EL1Resumer { save_area }
    }
}

impl ResumeHandle for EL1Resumer {
    unsafe fn resume(self) -> ! {
        panic!("not yet implemented");
    }
}

impl Process for ArchProcess {
    type E = ArchExecutor;
    type A = VSpace;

    /// Return the process ID.
    fn pid(&self) -> Pid {
        self.pid
    }

    fn vspace_mut(&mut self) -> &mut VSpace {
        &mut self.vspace
    }

    fn vspace(&self) -> &VSpace {
        &self.vspace
    }

    fn load(
        &mut self,
        pid: Pid,
        module: &Module,
        writeable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
        panic!("not yet implemented");
    }

    fn try_reserve_executors(
        &self,
        _how_many: usize,
        _affinity: atopology::NodeId,
    ) -> Result<(), TryReserveError> {
        panic!("not yet implemented");
    }

    fn get_executor(&mut self, for_region: atopology::NodeId) -> Result<Box<ArchExecutor>, KError> {
        panic!("not yet implemented");
    }

    fn allocate_executors(&mut self, memory: Frame) -> Result<usize, KError> {
        panic!("not yet implemented");
    }

    fn allocate_fd(&mut self) -> Option<(u64, &mut FileDescriptorEntry)> {
        panic!("not yet implemented");
    }

    fn deallocate_fd(&mut self, fd: usize) -> Result<usize, KError> {
        panic!("not yet implemented");
    }

    fn get_fd(&self, index: usize) -> &FileDescriptorEntry {
        panic!("not yet implemented");
    }

    fn pinfo(&self) -> &kpi::process::ProcessInfo {
        &self.pinfo
    }

    fn add_frame(&mut self, frame: Frame) -> Result<FrameId, KError> {
        panic!("not yet implemented");
    }

    fn get_frame(&mut self, frame_id: FrameId) -> Result<Frame, KError> {
        panic!("not yet implemented");
    }

    fn deallocate_frame(&mut self, fid: FrameId) -> Result<Frame, KError> {
        panic!("not yet implemented");
    }
}

impl Executor for ArchExecutor {
    type Resumer = ArchResumer;

    fn id(&self) -> Eid {
        self.eid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn vcpu_kernel(&self) -> *mut kpi::arch::VirtualCpu {
        panic!("not yet implemented");
    }

    /// Start the process (run it for the first time).
    fn start(&self) -> Self::Resumer {
        panic!("not yet implemented");
    }

    fn resume(&self) -> Self::Resumer {
        panic!("not yet implemented");
    }

    fn upcall(&self, vector: u64, exception: u64) -> Self::Resumer {
        panic!("not yet implemented");
    }

    fn maybe_switch_vspace(&self) {
        panic!("not yet implemented");
    }
}
