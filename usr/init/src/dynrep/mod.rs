// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ptr;
use log::info;

use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

use lineup::tls2::{Environment, SchedulerControlBlock};
use nr2::nr::{rwlock::RwLock, Dispatch, NodeReplicated};
use x86::bits64::paging::VAddr;

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
        let map = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(
            NUM_ENTRIES as usize,
            allocator,
        );
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

unsafe extern "C" fn bencher_trampoline(_arg1: *mut u8) -> *mut u8 {
    thread_routine();
    ptr::null_mut()
}

fn thread_routine() {
    let current_gtid = vibrio::syscalls::System::core_id().expect("Can't get core id");
    let mid = kpi::system::mid_from_gtid(current_gtid);
    info!("I am thread {:?} and I am on node {:?}", current_gtid, mid);
}

pub fn userspace_dynrep_test() {
    // Get system information
    let hwthreads = vibrio::syscalls::System::threads().expect("Cant get system topology");
    let current_gtid = vibrio::syscalls::System::core_id().expect("Can't get core id");
    let ncores = hwthreads.len();

    // Figure out how many clients there are - this will determine how many max replicas we use
    let mut nnodes = 0;
    for hwthread in hwthreads.iter() {
        // mid == machine id, otherwise referred to as client id
        let mid = kpi::system::mid_from_gtid(hwthread.id);
        if mid > nnodes {
            nnodes = mid;
        }
    }
    log::info!("Found {:?} client machines", nnodes);

    // Create data structure, with as many replicas as there are clients (assuming 1 numa node per client)
    // TODO: change # of replicas to nnodes
    let replicas = NonZeroUsize::new(1).unwrap();
    let nrht = NodeReplicated::<HashTable>::new(replicas, |_| 0).unwrap();

    // TODO: populate data structure
    let ttkn = nrht.register(0).unwrap();
    nrht.execute(OpRd::Get(0), ttkn).unwrap();

    let s = &vibrio::upcalls::PROCESS_SCHEDULER;

    let mut gtids = Vec::with_capacity(ncores);

    // We already have current core
    gtids.push(current_gtid);

    for hwthread in hwthreads.iter() {
        if hwthread.id != current_gtid {
            match vibrio::syscalls::Process::request_core(
                hwthread.id,
                VAddr::from(vibrio::upcalls::upcall_while_enabled as *const fn() as u64),
            ) {
                Ok(core_token) => {
                    gtids.push(core_token.gtid());
                    if gtids.len() == ncores {
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    log::error!("Can't spawn on {:?}: {:?}", hwthread.id, e);
                    break;
                }
            }
        }
    }
    assert!(ncores == gtids.len());
    info!("Spawned {} cores", ncores);

    s.spawn(
        32 * 4096,
        move |_| {
            let mut thandles = Vec::with_capacity(ncores);

            for core_index in 0..ncores {
                thandles.push(
                    Environment::thread()
                        .spawn_on_core(
                            Some(bencher_trampoline),
                            ncores as *mut u8,
                            gtids[core_index],
                        )
                        .expect("Can't spawn bench thread?"),
                );
            }

            for thandle in thandles {
                Environment::thread().join(thandle);
            }
        },
        ptr::null_mut(),
        current_gtid,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(current_gtid);
    while s.has_active_threads() {
        s.run(&scb);
    }
    info!("dynrep_test OK");
}
