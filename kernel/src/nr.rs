#![allow(unused)]

use node_replication::Dispatch;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum Op {
    HelloWorld(u32),
    Bye,
    Invalid,
}

impl Default for Op {
    fn default() -> Op {
        Op::Invalid
    }
}

#[derive(Eq, PartialEq)]
pub struct KernelNode {}

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
            Op::HelloWorld(v) => info!("Op::HelloWorld {}", v),
            Op::Bye => info!("Op::Bye"),
            Op::Invalid => panic!("Got invalid OP"),
        };
    }
}
