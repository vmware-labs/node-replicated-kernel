#![allow(unused)]

use crate::prelude::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use mlnr::{Dispatch, LogMapper, ReplicaToken};

pub struct Temp {
    counters: Vec<CachePadded<AtomicUsize>>,
}

impl Temp {
    fn increment(&self, index: usize) -> usize {
        self.counters[index].fetch_add(1, Ordering::Relaxed)
    }

    fn access(&self, index: usize) -> usize {
        self.counters[index].load(Ordering::Relaxed)
    }
}

impl Default for Temp {
    fn default() -> Self {
        let num_cores = 192;
        let mut counters = Vec::with_capacity(num_cores);
        for i in 0..num_cores {
            counters.push(Default::default());
        }
        Temp { counters }
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Modify {
    Increment(usize),
}

impl LogMapper for Modify {
    fn hash(&self) -> usize {
        0
    }
}

impl Default for Modify {
    fn default() -> Self {
        Modify::Increment(0)
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Access {
    Get,
}

impl LogMapper for Access {
    fn hash(&self) -> usize {
        0
    }
}

impl Dispatch for Temp {
    type ReadOperation = Access;
    type WriteOperation = Modify;
    type Response = Option<u64>;

    fn dispatch(&self, _op: Self::ReadOperation) -> Self::Response {
        Some(self.access(0) as u64)
    }

    fn dispatch_mut(&self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Modify::Increment(tid) => Some(self.increment(tid as usize) as u64),
        }
    }
}
