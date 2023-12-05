// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use log::info;
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

use alloc::sync::Arc;
use core::num::NonZeroUsize;
use nr2::nr::{NodeReplicated, rwlock::RwLock, Dispatch};

mod allocator;
use allocator::MyAllocator;

pub const NUM_ENTRIES: u64 = 50_000_000;

#[derive(Clone)]
struct HashTable {
    map: HashMap<u64, u64, DefaultHashBuilder, MyAllocator>,
}

impl Default for HashTable {
    fn default() -> Self {
        let allocator = MyAllocator::default();
        let map = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(NUM_ENTRIES as usize, allocator);
        HashTable { map }
    }
}

enum OpRd {
    Get(u64),
}

#[derive(PartialEq, Clone)]
enum OpWr {
    Put(u64, u64),
}

impl Dispatch for HashTable {
    type ReadOperation<'a> = OpRd;
    type WriteOperation = OpWr;
    type Response = Result<Option<u64>, ()>;

    fn dispatch<'a>(&self, op: Self::ReadOperation<'a>) -> Self::Response {
        match op {
            OpRd::Get(key) => {
                let val = self.map.get(&key);
                Ok(val.copied())
            }
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            OpWr::Put(key, val) => {
                let resp = self.map.insert(key, val);
                Ok(resp)
            }
        }
    }
}

pub fn userspace_dynrep_test() {
    let replicas = NonZeroUsize::new(1).unwrap();
    let nrht = NodeReplicated::<HashTable>::new(replicas, |_| { 0 }).unwrap();
    let ttkn = nrht.register(0).unwrap();
    nrht.execute(OpRd::Get(0), ttkn).unwrap();

    info!("dynrep_test OK");
}
