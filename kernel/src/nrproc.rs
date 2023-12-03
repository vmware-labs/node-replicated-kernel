// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::prelude::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use fallible_collections::FallibleVecGlobal;

use arrayvec::ArrayVec;
use fallible_collections::vec::FallibleVec;
use kpi::process::{FrameId, ProcessInfo};
use kpi::MemType;
use nr2::nr::{rwlock::RwLock, Dispatch, NodeReplicated, ThreadToken};
use spin::Once;

use crate::arch::process::PROCESS_TABLE;
use crate::error::{KError, KResult};
use crate::memory::vspace::{AddressSpace, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{
    Eid, Executor, Pid, Process, SliceAccess, UserSlice, MAX_FRAMES_PER_PROCESS, MAX_PROCESSES,
};

/// The tokens per core to access the process replicas.
#[thread_local]
pub(crate) static PROCESS_TOKEN: Once<ArrayVec<ThreadToken, { MAX_PROCESSES }>> = Once::new();

/// Initializes `PROCESS_TOKEN`.
///
/// Should be called on each core.
pub(crate) fn register_thread_with_process_replicas() {
    #[cfg(not(feature = "rackscale"))]
    let node = *crate::environment::NODE_ID;
    #[cfg(feature = "rackscale")]
    let node = 0; //*crate::environment::MACHINE_ID - 1; // 0;

    debug_assert!(PROCESS_TABLE.len() > node, "Invalid Node ID");

    PROCESS_TOKEN.call_once(|| {
        let mut tokens = ArrayVec::new();
        for pid in 0..MAX_PROCESSES {
            debug_assert!(PROCESS_TABLE.len() > pid, "Invalid PID");

            let token = PROCESS_TABLE[pid]
                .read(*crate::environment::MT_ID)
                .register(node);
            log::info!(
                "MT_ID is {}: {node} registered {pid} {token:?}",
                *crate::environment::MT_ID
            );
            tokens.push(token.expect("Need to be able to register"));
        }

        tokens
    });
}

/// A function we can "apply" on mutable slices of user-space memory.
///
/// This returns a (u64, u64) as opposed to the `SliceExecFn` which returns
/// nothing. This is because we call this from RPC handlers which eventually
/// need to return (u64, u64) to the process. Ideally the return type could just
/// be generic in some fun future?
type SliceExecMutFn<'buf> = Box<dyn Fn(&'buf mut [u8]) -> KResult<(u64, u64)>>;

/// A function we can "apply" on a non-mutable slice of user-space memory.
type SliceExecFn<'buf> = Box<dyn Fn(&'buf [u8]) -> KResult<()>>;

/// Immutable operations on the NrProcess.
pub(crate) enum ProcessOp<'buf> {
    ProcessInfo,
    MemResolve(VAddr),
    ReadSlice(UserSlice),
    ReadString(UserSlice),
    WriteSlice(&'buf mut UserSlice, &'buf [u8]),
    #[allow(unused)]
    ExecSliceMut(UserSlice, SliceExecMutFn<'buf>),
    ExecSlice(&'buf UserSlice, SliceExecFn<'buf>),
    GetPtRoot,
}

/// Mutable operations on the NrProcess.
#[derive(PartialEq, Clone, Debug)]
pub(crate) enum ProcessOpMut {
    Load(Pid, String, Vec<Frame>),

    /// Assign a core to a process.
    AssignExecutor(atopology::NodeId, kpi::system::GlobalThreadId),

    /// Assign a physical frame to a process (returns a FrameId).
    AllocateFrameToProcess(Frame),
    /// Remove a physical frame previosuly allocated to the process (returns a Frame).
    ReleaseFrameFromProcess(FrameId),

    #[cfg(feature = "rackscale")]
    DispatcherAllocation(Frame, kpi::system::MachineId),

    #[cfg(not(feature = "rackscale"))]
    DispatcherAllocation(Frame),

    MemMapFrame(VAddr, Frame, MapAction),
    MemMapDevice(Frame, MapAction),
    MemMapFrameId(VAddr, FrameId, MapAction),
    MemUnmap(VAddr),
}

/// Possible return values from the NrProcess.
#[derive(Debug, Clone)]
pub(crate) enum ProcessResult<E: Executor> {
    Ok,
    SysRetOk((u64, u64)),
    ProcessInfo(ProcessInfo),
    Executor(Box<E>),
    ExecutorsCreated(usize),
    MappedFrameId(PAddr, usize),
    Unmapped(Vec<TlbFlushHandle>),
    Resolved(PAddr, MapAction),
    FrameId(usize),
    Frame(Frame),
    ReadSlice(Arc<[u8]>),
    ReadString(String),
    PtRoot(PAddr),
}

pub(crate) trait ProcessManager {
    type Process: Process + Sync;

    #[allow(clippy::type_complexity)] // fix this once `associated_type_defaults` works
    fn process_table(
        &self,
    ) -> &ArrayVec<Arc<RwLock<NodeReplicated<NrProcess<Self::Process>>>>, MAX_PROCESSES>;
}

/// A node-replicated process.
#[derive(Clone)]
pub(crate) struct NrProcess<P: Process> {
    /// A list of all cores where the current process is running.
    active_cores: Vec<(kpi::system::GlobalThreadId, Eid)>,
    /// The process struct itself.
    process: Box<P>,
}

impl<P: Process> NrProcess<P> {
    pub(crate) fn new(process: Box<P>) -> NrProcess<P> {
        NrProcess {
            active_cores: Vec::new(),
            process,
        }
    }
}

impl<P: Process> NrProcess<P> {
    pub(crate) fn add_replica(pid: Pid, rid: usize) -> Result<Vec<TlbFlushHandle>, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        #[cfg(feature = "rackscale")]
        let max_nodes = *crate::environment::NUM_MACHINES;
        #[cfg(not(feature = "rackscale"))]
        let max_nodes = *crate::environment::NUM_NODES;

        debug_assert!(rid < max_nodes, "Invalid Node ID");
        log::info!("add_replica {pid} {rid}");
        // we use unmap of 0x0 to get a snapshot of where the core is running on
        let handle = NrProcess::<P>::unmap(pid, VAddr::from(0x0));
        if handle.is_err() {
            panic!("couldn't get snapshot");
        }

        PROCESS_TABLE[pid]
            .write(*crate::environment::MT_ID)
            .add_replica(rid)
            .expect("add_replica failed");
        log::debug!("added_replica {pid} {rid}");

        handle
    }

    pub(crate) fn remove_replica(pid: Pid, rid: usize) -> Result<Vec<TlbFlushHandle>, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        #[cfg(feature = "rackscale")]
        let max_nodes = *crate::environment::NUM_MACHINES;
        #[cfg(not(feature = "rackscale"))]
        let max_nodes = *crate::environment::NUM_NODES;

        debug_assert!(
            rid < max_nodes,
            "Invalid Node ID {rid} max_nodes {max_nodes}"
        );

        // we use unmap of 0x0 to get a snapshot of where the core is running on
        let handle = NrProcess::<P>::unmap(pid, VAddr::from(0x0));
        if handle.is_err() {
            panic!("couldn't get snapshot");
        }
        PROCESS_TABLE[pid]
            .write(*crate::environment::MT_ID)
            .remove_replica(rid)
            .expect("remove_replica failed");

        handle
    }

    pub(crate) fn load(
        pid: Pid,
        module_name: String,
        writeable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::Load(pid, module_name, writeable_sections),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::Ok) => Ok(()),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn resolve(pid: Pid, base: VAddr) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        debug_assert!(base.as_u64() < kpi::KERNEL_BASE, "Invalid base");
        let response = PROCESS_TABLE[pid].read(*crate::environment::MT_ID).execute(
            ProcessOp::MemResolve(base),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(ProcessResult::Resolved(paddr, _rights)) => Ok((paddr.as_u64(), 0x0)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn synchronize(pid: Pid) {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .sync(PROCESS_TOKEN.get().unwrap()[pid]);
    }

    pub(crate) fn map_device_frame(
        pid: Pid,
        frame: Frame,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::MemMapDevice(frame, action),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::Ok) => Ok((frame.base.as_u64(), frame.size() as u64)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn unmap(pid: Pid, base: VAddr) -> Result<Vec<TlbFlushHandle>, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::MemUnmap(base),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::Unmapped(handle)) => Ok(handle),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn map_frame_id(
        pid: Pid,
        frame_id: FrameId,
        base: VAddr,
        action: MapAction,
    ) -> Result<(PAddr, usize), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        //action.multiple_mappings(true);
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::MemMapFrameId(base, frame_id, action),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::MappedFrameId(paddr, size)) => Ok((paddr, size)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn map_frames(
        pid: Pid,
        base: VAddr,
        frames: Vec<Frame>,
        action: MapAction,
    ) -> Result<(u64, u64), KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let mut virtual_offset = 0;
        for frame in frames {
            let response = PROCESS_TABLE[pid]
                .read(*crate::environment::MT_ID)
                .execute_mut(
                    ProcessOpMut::MemMapFrame(base + virtual_offset, frame, action),
                    PROCESS_TOKEN.get().unwrap()[pid],
                );
            match response {
                Ok(ProcessResult::Ok) => {}
                e => unreachable!(
                    "Got unexpected response MemMapFrame {:?} {:?} {:?} {:?}",
                    e,
                    base + virtual_offset,
                    frame,
                    action
                ),
            }

            virtual_offset += frame.size();
        }

        Ok((base.as_u64(), virtual_offset as u64))
    }

    pub(crate) fn ptroot(pid: Pid) -> Result<PAddr, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute(ProcessOp::GetPtRoot, PROCESS_TOKEN.get().unwrap()[pid]);
        match response {
            Ok(ProcessResult::PtRoot(paddr)) => Ok(paddr),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn pinfo(pid: Pid) -> Result<ProcessInfo, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute(ProcessOp::ProcessInfo, PROCESS_TOKEN.get().unwrap()[pid]);
        match response {
            Ok(ProcessResult::ProcessInfo(pinfo)) => Ok(pinfo),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    fn try_assign_executor<A>(pm: &A, pid: Pid) -> Result<Box<P::E>, KError>
    where
        A: ProcessManager<Process = P>,
        P: Process + core::marker::Sync + 'static,
    {
        let gtid = *crate::environment::CORE_ID;
        let node = *crate::environment::NODE_ID;

        let response = pm.process_table()[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::AssignExecutor(gtid, node),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::Executor(executor)) => Ok(executor),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn allocate_executor<A>(pm: &A, pid: Pid) -> Result<Box<P::E>, KError>
    where
        A: ProcessManager<Process = P>,
        P: Process + core::marker::Sync + 'static,
    {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        let response = NrProcess::try_assign_executor(pm, pid);
        // If we didn't have dispatcher memory allocated, allocate and try again
        if let Err(KError::NoExecutorAllocated) = response {
            let node = *crate::environment::NODE_ID;
            super::process::allocate_dispatchers::<P>(pid, node)?;
            NrProcess::try_assign_executor(pm, pid)
        } else {
            response
        }
    }

    pub(crate) fn allocate_frame_to_process(pid: Pid, frame: Frame) -> Result<FrameId, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::AllocateFrameToProcess(frame),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::FrameId(fid)) => Ok(fid),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn release_frame_from_process(pid: Pid, fid: FrameId) -> Result<Frame, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        debug_assert!(fid < MAX_FRAMES_PER_PROCESS, "Invalid FID");
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                ProcessOpMut::ReleaseFrameFromProcess(fid),
                PROCESS_TOKEN.get().unwrap()[pid],
            );
        match response {
            Ok(ProcessResult::Frame(f)) => Ok(f),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn allocate_dispatchers(pid: Pid, frame: Frame) -> Result<usize, KError> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");

        #[cfg(feature = "rackscale")]
        let mid = *crate::environment::MACHINE_ID;
        let response = PROCESS_TABLE[pid]
            .read(*crate::environment::MT_ID)
            .execute_mut(
                #[cfg(not(feature = "rackscale"))]
                ProcessOpMut::DispatcherAllocation(frame),
                #[cfg(feature = "rackscale")]
                ProcessOpMut::DispatcherAllocation(frame, mid),
                PROCESS_TOKEN.get().unwrap()[pid],
            );

        match response {
            Ok(ProcessResult::ExecutorsCreated(how_many)) => Ok(how_many),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn userslice_to_arc_slice(from: UserSlice) -> Result<Arc<[u8]>, KError> {
        let response = PROCESS_TABLE[from.pid]
            .read(*crate::environment::MT_ID)
            .execute(
                ProcessOp::ReadSlice(from),
                PROCESS_TOKEN.get().unwrap()[from.pid],
            );
        match response {
            Ok(ProcessResult::ReadSlice(v)) => Ok(v),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn read_string_from_userspace(from: UserSlice) -> Result<String, KError> {
        let response = PROCESS_TABLE[from.pid]
            .read(*crate::environment::MT_ID)
            .execute(
                ProcessOp::ReadString(from),
                PROCESS_TOKEN.get().unwrap()[from.pid],
            );
        match response {
            Ok(ProcessResult::ReadString(s)) => Ok(s),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn write_to_userspace(to: &mut UserSlice, kbuf: &[u8]) -> Result<(), KError> {
        let pid = to.pid;

        let response = PROCESS_TABLE[pid].read(*crate::environment::MT_ID).execute(
            ProcessOp::WriteSlice(to, kbuf),
            PROCESS_TOKEN.get().unwrap()[pid],
        );
        match response {
            Ok(ProcessResult::Ok) => Ok(()),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    #[cfg(feature = "rackscale")]
    pub(crate) fn userspace_exec_slice_mut(
        on: UserSlice,
        f: Box<dyn Fn(&mut [u8]) -> KResult<(u64, u64)>>,
    ) -> Result<(u64, u64), KError> {
        let response = PROCESS_TABLE[on.pid]
            .read(*crate::environment::MT_ID)
            .execute(
                ProcessOp::ExecSliceMut(on, f),
                PROCESS_TOKEN.get().unwrap()[on.pid],
            );
        match response {
            Ok(ProcessResult::SysRetOk((a, b))) => Ok((a, b)),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }

    pub(crate) fn userspace_exec_slice<'a>(
        on: &'a UserSlice,
        f: Box<dyn Fn(&'a [u8]) -> KResult<()>>,
    ) -> Result<(), KError> {
        let response = PROCESS_TABLE[on.pid]
            .read(*crate::environment::MT_ID)
            .execute(
                ProcessOp::ExecSlice(on, f),
                PROCESS_TOKEN.get().unwrap()[on.pid],
            );
        match response {
            Ok(ProcessResult::Ok) => Ok(()),
            Err(e) => Err(e),
            _ => unreachable!("Got unexpected response"),
        }
    }
}

impl<P> Dispatch for NrProcess<P>
where
    P: Process,
    P::E: Copy,
{
    type ReadOperation<'buf> = ProcessOp<'buf>;
    type WriteOperation = ProcessOpMut;
    type Response = Result<ProcessResult<P::E>, KError>;

    fn dispatch<'buf>(&self, op: Self::ReadOperation<'_>) -> Self::Response {
        match op {
            ProcessOp::GetPtRoot => Ok(ProcessResult::PtRoot(self.process.vspace().root())),
            ProcessOp::ProcessInfo => Ok(ProcessResult::ProcessInfo(*self.process.pinfo())),
            ProcessOp::MemResolve(base) => {
                let (paddr, rights) = self.process.vspace().resolve(base)?;
                Ok(ProcessResult::Resolved(paddr, rights))
            }
            ProcessOp::ReadSlice(uslice) => {
                // We're going to copy what we read into this thing
                // TODO(panic+oom): need `try_new_uninit_slice` https://github.com/rust-lang/rust/issues/63291
                let mut buffer = Arc::<[u8]>::new_uninit_slice(uslice.len());
                let data = Arc::get_mut(&mut buffer).unwrap();
                uslice.with_slice(&*self.process, |ubuf| {
                    MaybeUninit::write_slice(data, ubuf);
                    Ok(())
                })?;
                let buffer = unsafe {
                    // Safety: `assume_init`
                    // - Plain-old-data, that we just copied into `buffer` above
                    // - uslice and buffer have the same length (buffer
                    //   initialized with uslice.len())
                    buffer.assume_init()
                };

                Ok(ProcessResult::ReadSlice(buffer))
            }
            ProcessOp::ReadString(uslice) => {
                let mut kbuf = Vec::try_with_capacity(uslice.len())?;
                uslice.with_slice(&*self.process, |ubuf| {
                    kbuf.extend_from_slice(ubuf);
                    Ok(())
                })?;
                Ok(ProcessResult::ReadString(String::from_utf8(kbuf)?))
            }
            ProcessOp::WriteSlice(uslice, kbuf) => {
                if uslice.len() != kbuf.len() {
                    return Err(KError::SliceLengthMismatchForWriting);
                }
                // Writing the data to the process' memory
                uslice.with_slice_mut(&*self.process, |ubuf| {
                    ubuf.copy_from_slice(kbuf);
                    Ok(())
                })?;
                Ok(ProcessResult::Ok)
            }
            ProcessOp::ExecSliceMut(uslice, closure) => {
                let (a, b) = uslice.with_slice_mut(&*self.process, closure)?;
                Ok(ProcessResult::SysRetOk((a, b)))
            }
            ProcessOp::ExecSlice(uslice, closure) => {
                uslice.with_slice(&*self.process, closure)?;
                Ok(ProcessResult::Ok)
            }
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            ProcessOpMut::Load(pid, module_name, writeable_sections) => {
                self.process.load(pid, module_name, writeable_sections)?;
                Ok(ProcessResult::Ok)
            }

            #[cfg(not(feature = "rackscale"))]
            ProcessOpMut::DispatcherAllocation(frame) => {
                let how_many = self.process.allocate_executors(frame)?;
                Ok(ProcessResult::ExecutorsCreated(how_many))
            }

            #[cfg(feature = "rackscale")]
            ProcessOpMut::DispatcherAllocation(frame, mid) => {
                let how_many = self.process.allocate_executors(frame, mid)?;
                Ok(ProcessResult::ExecutorsCreated(how_many))
            }

            ProcessOpMut::MemMapFrame(base, frame, action) => {
                crate::memory::KernelAllocator::try_refill_tcache(7, 0, MemType::Mem)?;
                self.process.vspace_mut().map_frame(base, frame, action)?;
                Ok(ProcessResult::Ok)
            }

            // Can be MapFrame with base supplied ...
            ProcessOpMut::MemMapDevice(frame, action) => {
                let base = VAddr::from(frame.base.as_u64());
                self.process.vspace_mut().map_frame(base, frame, action)?;
                Ok(ProcessResult::Ok)
            }

            ProcessOpMut::MemMapFrameId(base, frame_id, action) => {
                let (frame, _refcnt) = self.process.get_frame(frame_id)?;
                self.process.add_frame_mapping(frame_id, base)?;
                crate::memory::KernelAllocator::try_refill_tcache(7, 0, MemType::Mem)?;
                self.process.vspace_mut().map_frame(base, frame, action)?;
                Ok(ProcessResult::MappedFrameId(frame.base, frame.size))
            }

            ProcessOpMut::MemUnmap(vaddr) => {
                let shootdown_handle = if vaddr.as_u64() != 0x0 {
                    let shootdown_handle = self.process.vspace_mut().unmap(vaddr)?;
                    if shootdown_handle.flags.is_aliasable() {
                        self.process
                            .remove_frame_mapping(shootdown_handle.paddr, shootdown_handle.vaddr)
                            .expect("is_aliasable implies this op can't fail");
                    }
                    shootdown_handle
                } else {
                    TlbFlushHandle::new(0x0.into(), 0x0.into(), 0x0, MapAction::none())
                };

                let num_machines = *crate::environment::NUM_MACHINES;
                let mut shootdown_handles = Vec::try_with_capacity(num_machines)
                    .expect("not enough memory to make shootdown vector");
                for _i in 0..num_machines {
                    shootdown_handles.push(shootdown_handle.clone())
                }

                // Figure out which cores are running our current process
                // (this is where we send IPIs later)
                for (gtid, _eid) in self.active_cores.iter() {
                    shootdown_handles[kpi::system::mid_from_gtid(*gtid)]
                        .add_core(kpi::system::mtid_from_gtid(*gtid));
                }

                Ok(ProcessResult::Unmapped(shootdown_handles))
            }

            ProcessOpMut::AssignExecutor(gtid, region) => {
                #[cfg(not(feature = "rackscale"))]
                let executor = self.process.get_executor(region)?;

                #[cfg(feature = "rackscale")]
                let executor = self
                    .process
                    .get_executor(region, kpi::system::mid_from_gtid(gtid))?;

                let eid = executor.id();
                self.active_cores.try_push((gtid, eid))?;
                Ok(ProcessResult::Executor(executor))
            }

            ProcessOpMut::AllocateFrameToProcess(frame) => {
                let fid = self.process.add_frame(frame)?;
                Ok(ProcessResult::FrameId(fid))
            }

            ProcessOpMut::ReleaseFrameFromProcess(fid) => {
                let frame = self.process.deallocate_frame(fid)?;
                Ok(ProcessResult::Frame(frame))
            }
        }
    }
}
