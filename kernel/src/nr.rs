#![allow(unused)]

use crate::prelude::*;
use alloc::sync::Arc;
use alloc::vec::Vec;

use hashbrown::HashMap;
use node_replication::Dispatch;

use crate::arch::Module;
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::{Frame, PAddr, VAddr};
use crate::process::{Eid, Executor, Pid, Process};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Op {
    ProcCreate(&'static Module),
    ProcDestroy(Pid),
    ProcInstallVCpuArea(Pid, u64),
    ProcAllocIrqVector,
    ProcRaiseIrq,
    DispAlloc(Pid, Frame),
    DispDealloc,
    DispSchedule,
    MemMapFrames(Pid, VAddr, Frame, MapAction), // Vec<Frame> doesn't implement copy
    MemMapFrame(Pid, VAddr, Frame, MapAction),
    MemMapDevice,
    MemAdjust,
    MemUnmap,
    MemResolve(Pid, VAddr),
    Invalid,
}

impl Default for Op {
    fn default() -> Self {
        Op::Invalid
    }
}

#[derive(Copy, Eq, PartialEq, Debug, Clone)]
pub enum NodeResult<E: Executor> {
    ProcCreated(Pid),
    ProcDestroyed,
    VectorAllocated(u64),
    ReqExecutor(*mut E),
    Mapped,
    Adjusted,
    Unmapped,
    Resolved(PAddr, MapAction),
    Error,
}

impl<E: Executor> Default for NodeResult<E> {
    fn default() -> Self {
        NodeResult::Error
    }
}

pub struct KernelNode<P: Process> {
    current_pid: Pid,
    process_map: HashMap<Pid, Box<P>>,
}

impl<P: Process> Default for KernelNode<P> {
    fn default() -> KernelNode<P> {
        KernelNode {
            current_pid: 1,
            process_map: HashMap::with_capacity(256),
        }
    }
}

impl<P> Dispatch for KernelNode<P>
where
    P: Process,
    P::E: Copy,
{
    type Operation = Op;
    type Response = NodeResult<P::E>;

    fn dispatch(&mut self, op: Self::Operation) -> Self::Response {
        match op {
            Op::ProcCreate(module) => match P::new(module, self.current_pid) {
                Ok(process) => {
                    //self.process_map.try_reserve(1);
                    let pid = self.current_pid;
                    self.process_map.insert(pid, Box::new(process));
                    self.current_pid += 1;
                    NodeResult::ProcCreated(pid)
                }
                Err(e) => {
                    error!("Failed to create process {:?}", e);
                    NodeResult::Error
                }
            },
            Op::ProcDestroy(pid) => {
                // TODO(correctness): This is just a trivial,
                // wrong implementation at the moment
                let process = self.process_map.remove(&pid);
                if process.is_some() {
                    drop(process);
                    NodeResult::ProcDestroyed
                } else {
                    error!("Process not found");
                    NodeResult::Error
                }
            }
            Op::ProcInstallVCpuArea(_, _) => unreachable!(),
            Op::ProcAllocIrqVector => unreachable!(),
            Op::ProcRaiseIrq => unreachable!(),
            Op::DispAlloc(pid, frame) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let p = process_lookup.expect("TODO: DispAlloc process lookup failed");
                p.allocate_executors(frame)
                    .expect("Can't allocate dispatchers");
                let executor = p
                    .get_executor(0) // TODO (fixnow): Hard-coded 0
                    .expect("Can't get an executor for process");
                //NodeResult::ReqExecutor(executor)
                NodeResult::ReqExecutor(Box::into_raw(executor))
            }
            Op::DispDealloc => unreachable!(),
            Op::DispSchedule => unreachable!(),
            Op::MemMapFrames(pid, base, frames, action) => unimplemented!("MemMapFrames"),
            Op::MemMapFrame(pid, base, frame, action) => {
                let process_lookup = self.process_map.get_mut(&pid);
                let kcb = crate::kcb::get_kcb();
                let mut pmanager = kcb.mem_manager();

                let p = process_lookup.expect("TODO: MemMapFrame process lookup failed");
                info!("base {:?} frame {:?} action {:?}", base, frame, action);
                p.vspace()
                    .map_frame(base, frame, action, &mut *pmanager)
                    .expect("TODO: MemMapFrame map_frame failed");
                NodeResult::Mapped
            }
            Op::MemMapDevice => unreachable!(),
            Op::MemAdjust => unreachable!(),
            Op::MemUnmap => unreachable!(),
            Op::MemResolve(pid, base) => unimplemented!("MemResolve"),
            Op::Invalid => unreachable!("Got invalid OP"),
        }
    }
}
