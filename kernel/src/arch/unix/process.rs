// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A dummy process implementation for the unix platform.
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bootloader_shared::Module;
use core::alloc::Allocator;
use core::cell::RefCell;
use core::ops::{Deref, DerefMut};
use x86::current::paging::PAddr;

use arrayvec::ArrayVec;
use kpi::process::FrameId;
use lazy_static::lazy_static;

use node_replication::{Dispatch, Log, Replica};

use crate::arch::kcb::get_kcb;
use crate::error::{KError, KResult};
use crate::fs::fd::FileDescriptorEntry;
use crate::fs::MAX_FILES_PER_PROCESS;
use crate::memory::detmem::DA;
use crate::memory::vspace::MapAction;
use crate::memory::vspace::{AddressSpace, TlbFlushHandle};
use crate::memory::{Frame, VAddr, LARGE_PAGE_SIZE};
use crate::nrproc::NrProcess;
use crate::process::{
    Eid, Executor, FrameManagement, Pid, Process, ResumeHandle, MAX_FRAMES_PER_PROCESS,
    MAX_PROCESSES,
};

use super::debug;
use super::vspace::VSpace;
use super::MAX_NUMA_NODES;

/// The process model of the current architecture.
pub(crate) type ArchProcess = UnixProcess;

/// A handle to the currently active (scheduled on the core) process.
#[thread_local]
pub(crate) static CURRENT_EXECUTOR: RefCell<Option<Box<UnixThread>>> = RefCell::new(None);

pub(crate) fn has_executor() -> bool {
    CURRENT_EXECUTOR.borrow().is_some()
}

pub(crate) fn current_pid() -> KResult<Pid> {
    Err(KError::ProcessNotSet)
}

pub(crate) fn with_user_space_access_enabled<F, R>(f: F) -> KResult<R>
where
    F: FnOnce() -> KResult<R>,
{
    f()
}

#[allow(clippy::boxed_local)]
pub(crate) fn swap_current_executor(_current_executor: Box<UnixThread>) -> Option<Box<UnixThread>> {
    None
}

lazy_static! {
    pub(crate) static ref PROCESS_TABLE: ArrayVec<ArrayVec<Arc<Replica<'static, NrProcess<UnixProcess>>>, MAX_PROCESSES>, MAX_NUMA_NODES> = {
        // Want at least one replica...
        let numa_nodes = core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes());

        let mut numa_cache = ArrayVec::new();
        for _n in 0..numa_nodes {
            let process_replicas = ArrayVec::new();
            debug_assert!(!numa_cache.is_full(), "Ensured by loop range");
            numa_cache.push(process_replicas)
        }

        for pid in 0..MAX_PROCESSES {
                let log = Arc::try_new(Log::<<NrProcess<UnixProcess> as Dispatch>::WriteOperation>::new(
                    LARGE_PAGE_SIZE,
                )).expect("Can't initialize processes, out of memory.");

            let da = DA::new().expect("Can't initialize process deterministic memory allocator");
            for node in 0..numa_nodes {
                let pcm = super::kcb::per_core_mem();
                assert!(pcm.set_mem_affinity(node as atopology::NodeId).is_ok());

                debug_assert!(!numa_cache[node].is_full(), "Ensured by loop range");


                let p = Box::try_new(UnixProcess::new(pid, Box::new(da.clone())).expect("Can't create process during init")).expect("Not enough memory to initialize processes");
                let nrp = NrProcess::new(p, Box::new(da.clone()));

                numa_cache[node].push(Replica::<NrProcess<UnixProcess>>::with_data(&log, nrp));

                debug_assert_eq!(*crate::environment::NODE_ID, 0, "Expect initialization to happen on node 0.");
                assert!(pcm.set_mem_affinity(0).is_ok());
            }
        }

        numa_cache
    };
}

pub(crate) struct ArchProcessManagement;

impl crate::nrproc::ProcessManager for ArchProcessManagement {
    type Process = UnixProcess;

    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    > {
        &super::process::PROCESS_TABLE
    }
}

#[derive(Debug, Default)]
pub(crate) struct UnixProcess {
    pid: Pid,
    vspace: VSpace,
    /// File descriptors for the opened file.
    fds: ArrayVec<Option<FileDescriptorEntry>, MAX_FILES_PER_PROCESS>,
    pinfo: kpi::process::ProcessInfo,
    /// Physical frame objects registered to the process.
    pub frames: ArrayVec<Option<Frame>, MAX_FRAMES_PER_PROCESS>,
}

impl UnixProcess {
    fn new(pid: Pid, _allocator: Box<dyn Allocator + Send + Sync>) -> Result<Self, KError> {
        Ok(UnixProcess {
            pid,
            vspace: VSpace::new(),
            ..Default::default()
        })
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct UnixThread {
    pub eid: Eid,
    pub pid: Pid,
}

impl PartialEq<UnixThread> for UnixThread {
    fn eq(&self, other: &UnixThread) -> bool {
        self.pid == other.pid && self.eid == other.eid
    }
}
pub(crate) struct UnixResumeHandle {}

impl ResumeHandle for UnixResumeHandle {
    unsafe fn resume(self) -> ! {
        debug::shutdown(super::ExitReason::Ok)
    }
}

impl Executor for UnixThread {
    type Resumer = UnixResumeHandle;

    fn id(&self) -> Eid {
        self.eid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn start(&self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn resume(&self) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn upcall(&self, _vector: u64, _exception: u64) -> Self::Resumer {
        UnixResumeHandle {}
    }

    fn maybe_switch_vspace(&self) {}

    fn vcpu_kernel(&self) -> *mut kpi::arch::VirtualCpu {
        core::ptr::null_mut()
    }
}

impl Process for UnixProcess {
    type E = UnixThread;
    type A = VSpace;

    fn load(
        &mut self,
        _pid: Pid,
        _module_name: String,
        _writable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
        self.vspace.map_frame(
            VAddr::from(0x2000_0000),
            Frame::new(PAddr::zero(), 0x0, 0x0),
            MapAction::none(),
        )
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn try_reserve_executors(
        &self,
        _how_many: usize,
        _affinity: atopology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError> {
        Ok(())
    }

    fn allocate_executors(&mut self, _frame: Frame) -> Result<usize, KError> {
        Ok(0)
    }

    fn vspace_mut(&mut self) -> &mut Self::A {
        &mut self.vspace
    }

    fn vspace(&self) -> &VSpace {
        &self.vspace
    }

    fn get_executor(&mut self, _for_region: atopology::NodeId) -> Result<Box<Self::E>, KError> {
        Ok(Box::default())
    }

    fn allocate_fd(&mut self) -> Option<(u64, &mut FileDescriptorEntry)> {
        if let Some(fid) = self.fds.iter().position(|fd| fd.is_none()) {
            self.fds[fid] = Some(Default::default());
            Some((fid as u64, self.fds[fid].as_mut().unwrap()))
        } else {
            None
        }
    }

    fn deallocate_fd(&mut self, fd: usize) -> Result<usize, KError> {
        match self.fds.get_mut(fd) {
            Some(fdinfo) => match fdinfo {
                Some(info) => {
                    log::debug!("deallocating: {:?}", info);
                    *fdinfo = None;
                    Ok(fd)
                }
                None => Err(KError::InvalidFileDescriptor),
            },
            None => Err(KError::InvalidFileDescriptor),
        }
    }

    fn get_fd(&self, index: usize) -> &FileDescriptorEntry {
        self.fds[index].as_ref().unwrap()
    }

    fn pinfo(&self) -> &kpi::process::ProcessInfo {
        &self.pinfo
    }
}

impl FrameManagement for UnixProcess {
    fn add_frame(&mut self, frame: Frame) -> Result<FrameId, KError> {
        Err(KError::InvalidFrameId)
    }

    fn get_frame(&mut self, frame_id: FrameId) -> Result<(Frame, usize), KError> {
        Err(KError::InvalidFrameId)
    }

    fn add_frame_mapping(&mut self, frame_id: FrameId, vaddr: VAddr) -> Result<(), KError> {
        Err(KError::InvalidFrameId)
    }

    fn remove_frame_mapping(&mut self, paddr: PAddr, _vaddr: VAddr) -> Result<(), KError> {
        Err(KError::InvalidFrameId)
    }

    fn deallocate_frame(&mut self, fid: FrameId) -> Result<Frame, KError> {
        Err(KError::InvalidFrameId)
    }
}

pub(crate) fn spawn(binary: &'static str) -> Result<Pid, KError> {
    let pid = crate::process::make_process::<UnixProcess>(binary)?;
    Ok(0)
}
