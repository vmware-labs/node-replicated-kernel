#![allow(unused)]

use node_replication::Dispatch;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum Op {
    NewProcess,
    DestroyProcess,
    AllocateProcessor,
    DeallocateProcessor,
    Schedule,
    Map,
    Unmap,
    Bye,
    Invalid,
}

impl Default for Op {
    fn default() -> Op {
        Op::Invalid
    }
}

#[derive(Eq, PartialEq)]
pub struct KernelNode {
    // HashMap of processes
}

impl Default for KernelNode {
    fn default() -> KernelNode {
        KernelNode {}
    }
}

impl Dispatch for KernelNode {
    type Operation = Op;
    type Response = ();

    fn dispatch(&mut self, op: Self::Operation) -> Self::Response {
        match op {
            Op::NewProcess => unreachable!(),
            Op::DestroyProcess => unreachable!(),
            Op::AllocateProcessor => unreachable!(),
            Op::DeallocateProcessor => unreachable!(),
            Op::Schedule => unreachable!(),
            Op::Map => unreachable!(),
            Op::Unmap => unreachable!(),
            Op::Bye => unreachable!(),
            Op::Invalid => panic!("Got invalid OP"),
        };
    }
}
