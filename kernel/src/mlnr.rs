#![allow(unused)]

use core::sync::atomic::{AtomicUsize, Ordering};
use mlnr::{Dispatch, LogMapper, ReplicaToken};

pub struct Temp {
    counter: AtomicUsize,
}

impl Temp {
    fn increment(&self) -> usize {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    fn access(&self) -> usize {
        self.counter.load(Ordering::Relaxed)
    }
}

impl Default for Temp {
    fn default() -> Self {
        Temp {
            counter: AtomicUsize::new(0),
        }
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Modify {
    Increment(u64),
}

impl LogMapper for Modify {
    fn hash(&self) -> usize {
        0
    }
}

impl Default for Modify {
    fn default() -> Self {
        Modify::Increment(1)
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
        Some(self.access() as u64)
    }

    fn dispatch_mut(&self, _op: Self::WriteOperation) -> Self::Response {
        Some(self.increment() as u64)
    }
}
