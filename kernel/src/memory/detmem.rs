//! A deterministic memory provider that makes sure all allocations will succeed
//! on either all the replicas or none.
//!
//! The general idea is to maintain a set of queues (one for each replica), if
//! the higher level memory allocator for an NR data-structure runs out of
//! memory it will call `DeterministicAlloc.alloc` which ensures the
//! allocation either succeeds for all replicas or none (e.g., makes allocations
//! deterministic).

#![allow(warnings)] // For now...

use alloc::alloc::{alloc, dealloc};
use alloc::sync::Arc;
use core::alloc::Layout;
use core::alloc::{AllocError, Allocator};
use core::ptr::{self, NonNull};

use arrayvec::ArrayVec;
use atopology::MACHINE_TOPOLOGY;
use crossbeam_utils::CachePadded;
use log::info;
use spin::Mutex;

use crate::arch::kcb::per_core_mem;
use crate::arch::MAX_NUMA_NODES;
use crate::environment;
use crate::error::KError;
use crate::mpmc::Queue;

/// Makes allocation failures are deterministic (across all replicas) when used
/// within a replica.
pub(crate) struct DeterministicAlloc {
    /// Queues that store allocations results (allocated by the leading replica
    /// -- the replica that's most ahead in processing the log) until the
    /// replicas that are behind pick them up.
    ///
    /// We store the Layout and address (as u64 but it's really a *mut u8) for
    /// every allocation. Layout is technically not necessary (but used to
    /// sanity check the code).
    qs: ArrayVec<CachePadded<Queue<(Layout, u64)>>, MAX_NUMA_NODES>,
    /// Mutex that needs to be acquired when a leading replica needs to allocate
    /// for all replicas.
    fill: CachePadded<Mutex<()>>,
}

impl DeterministicAlloc {
    pub(crate) fn new() -> Result<Self, KError> {
        #[cfg(feature = "rackscale")]
        unreachable!("The deterministic allocator should not be used for rackscale builds");

        DeterministicAlloc::new_with_nodes(atopology::MACHINE_TOPOLOGY.num_nodes())
    }

    pub(crate) fn new_with_nodes(nodes: usize) -> Result<Self, KError> {
        assert!(
            nodes < MAX_NUMA_NODES,
            "Can't have more nodes than MAX_NUMA_NODES"
        );

        // Make sure we have at least 1 node
        let nodes = core::cmp::max(1, nodes);

        // Need to figure out this capacity; it is hard to determine,
        // something like: (#allocations of write op in NR with most
        // allocations)*(max log entries till GC)
        const ALLOC_CAP: usize = 32_000;

        let mut qs = ArrayVec::new();
        for _i in 0..nodes {
            qs.push(CachePadded::new(Queue::with_capacity(ALLOC_CAP)?));
        }

        Ok(Self {
            fill: CachePadded::new(Mutex::new(())),
            qs,
        })
    }

    pub(crate) fn alloc(&self, l: Layout) -> *mut u8 {
        let pcm = per_core_mem();
        let nid = *crate::environment::NODE_ID;

        if let Some((rl, ptr)) = self.qs[nid].pop() {
            // Queue wasn't empty; the leading replica already allocated on our
            // behalf
            if rl != l {
                info!("nid = {}", nid);
                assert_eq!(rl, l, "Layouts don't match");
            }
            ptr as *mut u8
        } else {
            // Need to request more in a deterministic way, so we acquire the
            // global lock (we are likely the leading replica)
            let _lock = self.fill.lock();

            if let Some((rl, ptr)) = self.qs[nid].pop() {
                // In the rare case that someone else already acquired `fill`,
                // we are done
                assert_eq!(rl, l, "Layouts don't match");
                return ptr as *mut u8;
            } else {
                // Now that we locked `fill`, perform allocation for all
                // replicas

                let mut allocs = ArrayVec::<*mut u8, MAX_NUMA_NODES>::new();
                for i in 0..self.qs.len() {
                    pcm.set_mem_affinity(i);
                    allocs.push(unsafe { alloc(l) });
                }
                pcm.set_mem_affinity(nid);
                // Check if any of the allocation failed:
                let succeeded = allocs.iter().filter(|e| e.is_null()).count() == 0;
                if succeeded {
                    // If we could allocate on every node, push all results to
                    // the queues
                    for i in 0..self.qs.len() {
                        if i != nid {
                            self.qs[i]
                                .push((l, allocs[i] as u64))
                                .expect("Can't push (1)");
                        }
                    }
                } else {
                    // If we didn't succeed to allocate on all nodes
                    for i in 0..self.qs.len() {
                        pcm.set_mem_affinity(i);
                        // Free any allocations that may have succeeded
                        if !allocs[i].is_null() {
                            unsafe { dealloc(allocs[i], l) };
                        }
                        // Set all allocation results to NULL
                        self.qs[i].push((l, 0x0)).expect("Can't push (2)");
                    }
                    pcm.set_mem_affinity(nid);
                }

                // Return allocation for current queue
                allocs[nid] as *mut u8
            }
        }
    }

    pub(crate) fn dealloc(ptr: *mut u8, l: Layout) {
        // dealloc just goes to the underlying allocator
        unsafe { dealloc(ptr, l) }
    }
}

#[derive(Clone)]
pub(crate) struct DA(Arc<DeterministicAlloc>);

impl DA {
    pub(crate) fn new() -> Result<Self, KError> {
        Ok(DA(Arc::try_new(DeterministicAlloc::new()?)?))
    }
}

unsafe impl Allocator for DA {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = self.0.alloc(layout);
        if !ptr.is_null() {
            Ok(unsafe {
                let nptr = NonNull::new_unchecked(ptr);
                NonNull::slice_from_raw_parts(nptr, layout.size())
            })
        } else {
            Err(AllocError)
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        DeterministicAlloc::dealloc(ptr.as_ptr(), layout);
    }
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use core::alloc::Allocator;
    use core::alloc::Layout;

    use core::borrow::BorrowMut;
    use std::thread;

    use rand::rngs::SmallRng;
    use rand::Rng;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn det_mem_provider() -> Result<(), KError> {
        const ITERATIONS: usize = 500;
        const SEED: [u8; 32] = [1; 32];
        const MAX_REPLICAS: usize = 4;

        let mut threads = Vec::with_capacity(MAX_REPLICAS);
        let memalloc = Arc::new(DeterministicAlloc::new_with_nodes(MAX_REPLICAS)?);

        for i in 0..MAX_REPLICAS {
            let memalloc = memalloc.clone();
            threads.push(thread::spawn(move || {
                {
                    let nid = crate::environment::NODE_ID.as_mut_ptr();
                    // Safety: Just for testing set a dummy node-id; we have
                    // exclusive access
                    unsafe { *nid = i % MAX_REPLICAS };
                }
                let mut order: Vec<(Layout, u64)> = Vec::with_capacity(ITERATIONS);

                // Use same RNG on all thread for deterministic allocation (as would
                // be the case with NR):
                let mut rng = SmallRng::from_seed(SEED);

                for _i in 0..ITERATIONS {
                    let l = Layout::from_size_align(rng.gen_range(16..128), 8).unwrap();
                    order.push((l, memalloc.alloc(l) as u64));
                }

                order
            }));
        }
        // Wait for all the threads to finish
        let mut layouts = Vec::with_capacity(MAX_REPLICAS);
        let mut pointers = Vec::with_capacity(MAX_REPLICAS);

        // Check that all layouts are handed out in the same order again
        fn is_all_same<T: PartialEq>(arr: &[T]) -> bool {
            arr.windows(2).all(|w| w[0] == w[1])
        }

        // Check that all pointers handed out are unique (we don't mess up regular
        // allocation)
        fn is_all_disjoint_or_zero(pointers: &Vec<Vec<u64>>) -> bool {
            use std::collections::HashSet;
            let mut set = HashSet::with_capacity(MAX_REPLICAS * ITERATIONS);
            for plist in pointers {
                for ptr in plist {
                    if *ptr == 0x0 {
                        // Skip null ptr
                        continue;
                    }

                    if !set.contains(&ptr) {
                        set.insert(ptr);
                    } else {
                        return false;
                    }
                }
            }

            true
        }

        // If one allocation fails (is null), the allocation on other replicas
        // should fail too
        fn is_deterministic(pointers: &Vec<Vec<u64>>) -> bool {
            if pointers.len() == 1 {
                true
            } else {
                for (idx, ptr) in pointers[0].iter().enumerate() {
                    if *ptr == 0x0 {
                        for other in pointers[1..pointers.len()].iter() {
                            assert_eq!(other[idx], 0x0, "Must also be null");
                        }
                    }
                }
                true
            }
        }

        for thread in threads {
            let result = thread.join().unwrap();
            let (layout, pointer): (Vec<_>, Vec<_>) = result.iter().cloned().unzip();

            layouts.push(layout);
            pointers.push(pointer);
        }

        assert!(is_all_same(&layouts));
        assert!(is_all_disjoint_or_zero(&pointers));
        assert!(is_deterministic(&pointers));

        Ok(())
    }
}
