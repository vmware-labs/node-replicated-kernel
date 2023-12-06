// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ptr;
use log::info;

use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use lineup::tls2::{Environment, SchedulerControlBlock};
use nr2::nr::{Dispatch, NodeReplicated, ThreadToken};
use rawtime::Instant;
use x86::bits64::paging::VAddr;
use x86::random::rdrand64;

mod allocator;
use allocator::MyAllocator;

pub const NUM_ENTRIES: u64 = 50_000_000;

static POOR_MANS_BARRIER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct HashTable {
    map: HashMap<u64, u64, DefaultHashBuilder, MyAllocator>,
}

impl Default for HashTable {
    fn default() -> Self {
        let allocator = MyAllocator {};
        let mut map = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(
            NUM_ENTRIES as usize,
            allocator,
        );
        for i in 0..NUM_ENTRIES {
            match map.insert(i, NUM_ENTRIES - i) {
                None => {}
                Some(_) => panic!("Key should not exist already"),
            }
        }
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
    type Response = Result<u64, ()>;

    fn dispatch<'a>(&self, op: Self::ReadOperation<'a>) -> Self::Response {
        match op {
            OpRd::Get(key) => match self.map.get(&key) {
                Some(val) => Ok(*val),
                None => Err(()),
            },
        }
    }

    fn dispatch_mut(&mut self, op: Self::WriteOperation) -> Self::Response {
        match op {
            OpWr::Put(key, val) => match self.map.insert(key, val) {
                None => Ok(0),
                Some(_) => Err(()),
            },
        }
    }
}

fn run_bench(
    mid: usize,
    core_id: usize,
    ttkn: ThreadToken,
    replica: Arc<NodeReplicated<HashTable>>,
) {
    let mut random_key: u64 = 0;
    let batch_size = 64;
    let duration = 5;

    let mut iterations = 0;
    while iterations <= duration {
        let mut ops = 0;
        let start = Instant::now();
        while start.elapsed().as_secs() < 1 {
            for i in 0..batch_size {
                unsafe { rdrand64(&mut random_key) };
                random_key = random_key % NUM_ENTRIES;
                let _ = replica.execute(OpRd::Get(random_key), ttkn).unwrap();
                ops += 1;
            }
        }
        info!("dynhash,{},{},{},{}", mid, core_id, iterations, ops);
        iterations += 1;
    }
}

unsafe extern "C" fn bencher_trampoline(args: *mut u8) -> *mut u8 {
    let current_gtid = vibrio::syscalls::System::core_id().expect("Can't get core id");
    let mid = kpi::system::mid_from_gtid(current_gtid);

    let replica: Arc<NodeReplicated<HashTable>> =
        Arc::from_raw(args as *const NodeReplicated<HashTable>);
    let ttkn = replica.register(mid - 1).unwrap();

    // Synchronize with all cores
    POOR_MANS_BARRIER.fetch_sub(1, Ordering::Release);
    while POOR_MANS_BARRIER.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }

    run_bench(mid, current_gtid, ttkn, replica.clone());
    ptr::null_mut()
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
    // TODO: change this to change number of replicas
    let num_replicas = NonZeroUsize::new(nnodes).unwrap(); // NonZeroUsize::new(1).unwrap();

    let replicas = Arc::new(NodeReplicated::<HashTable>::new(num_replicas, |_| 0).unwrap());

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
            POOR_MANS_BARRIER.store(ncores, Ordering::SeqCst);

            for core_index in 0..ncores {
                thandles.push(
                    Environment::thread()
                        .spawn_on_core(
                            Some(bencher_trampoline),
                            Arc::into_raw(replicas.clone()) as *const _ as *mut u8,
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
