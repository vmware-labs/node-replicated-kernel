#![allow(unused)]

use crate::prelude::*;

use hashbrown::HashMap;

use crate::arch::Module;
use crate::process::{Eid, Executor, Pid, Process};

use node_replication::Dispatch;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Op {
    ProcCreate(&'static Module),
    ProcDestroy(Pid),
    ProcInstallVCpuArea(Pid, u64),
    ProcAllocIrqVector,
    ProcRaiseIrq,
    DispAlloc,
    DispDealloc,
    DispSchedule,
    MemMapFrames,
    MemMapFrame,
    MemMapDevice,
    MemAdjust,
    MemUnmap,
    MemResolve,
    Invalid,
}

impl Default for Op {
    fn default() -> Self {
        Op::Invalid
    }
}

#[derive(Copy, Eq, PartialEq, Debug, Clone)]
pub enum NodeResult {
    ProcCreated(Pid),
    ProcDestroyed,
    VectorAllocated(u64),
    DispAllocated(Eid),
    DispDeallocated,
    DispSchedule(Eid),
    Mapped,
    Adjusted,
    Unmapped,
    Resolved,
    Error,
}

impl Default for NodeResult {
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

impl<P: Process> Dispatch for KernelNode<P> {
    type Operation = Op;
    type Response = NodeResult;

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
            Op::DispAlloc => unreachable!(),
            Op::DispDealloc => unreachable!(),
            Op::DispSchedule => unreachable!(),
            Op::MemMapFrames => unreachable!(),
            Op::MemMapFrame => unreachable!(),
            Op::MemMapDevice => unreachable!(),
            Op::MemAdjust => unreachable!(),
            Op::MemUnmap => unreachable!(),
            Op::MemResolve => unreachable!(),
            Op::Invalid => unreachable!("Got invalid OP"),
        }
    }
}
