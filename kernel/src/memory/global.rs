// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! GlobalMemory is the lowest level memory manager that holds all memory in the
//! beginning.

use core::fmt;

use arrayvec::ArrayVec;
use log::trace;
use spin::Mutex;

use crate::arch::MAX_NUMA_NODES;
use crate::prelude::*;

use super::backends::PhysicalPageProvider;
use super::frame::Frame;
use super::mcache;
use crate::arch::memory::{paddr_to_kernel_vaddr, PAddr};
use crate::arch::memory::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

/// How many initial physical memory regions we support.
pub(crate) const MAX_PHYSICAL_REGIONS: usize = 64;

/// Represents the global memory system in the kernel.
///
/// `node_caches` and and `emem` can be accessed concurrently and are protected
/// by a simple spin-lock (for reclamation and allocation).
///
/// TODO(perf): This may need a more elaborate scheme in the future.
#[derive(Default)]
pub(crate) struct GlobalMemory {
    /// Holds a small amount of memory for every NUMA node.
    ///
    /// Used to initialize the system.
    pub(crate) emem: ArrayVec<Mutex<mcache::FrameCacheSmall>, MAX_NUMA_NODES>,

    /// All node-caches in the system (one for every NUMA node).
    pub(crate) node_caches:
        ArrayVec<CachePadded<Mutex<&'static mut mcache::FrameCacheLarge>>, MAX_NUMA_NODES>,
}

impl GlobalMemory {
    /// Construct a new global memory object from a range of initial memory frames.
    /// This is typically invoked quite early (we're setting up support for memory allocation).
    ///
    /// We first chop off a small amount of memory from the frames to construct an early
    /// FrameCacheSmall (for every NUMA node). Then we construct the big node-caches (FrameCacheLarge) and
    /// populate them with remaining (hopefully a lot) memory.
    ///
    /// When this completes we have a bunch of global NUMA aware memory allocators that
    /// are protected by spin-locks. `GlobalMemory` together with the core-local allocators
    /// forms the tracking for our memory allocation system.
    ///
    /// # Safety
    /// Pretty unsafe as we do lot of conjuring objects from frames to allocate memory
    /// for our allocators.
    /// A client needs to ensure that our frames are valid memory, and not yet
    /// being used anywhere yet.
    /// The good news is that we only invoke this once during bootstrap.
    pub unsafe fn new(
        mut memory: ArrayVec<Frame, MAX_PHYSICAL_REGIONS>,
    ) -> Result<GlobalMemory, KError> {
        assert!(memory.is_sorted_by(|a, b| a.affinity.partial_cmp(&b.affinity)));

        debug_assert!(!memory.is_empty());
        let mut gm = GlobalMemory::default();

        // How many NUMA nodes are there in the system
        let max_affinity: usize = memory
            .iter()
            .map(|f| f.affinity)
            .max()
            .expect("Need at least some frames")
            + 1;

        // Construct the `emem`'s for all NUMA nodes:
        let mut cur_affinity = 0;
        // Top of the frames that we didn't end up using for the `emem` construction
        let mut leftovers: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
        for frame in memory.iter_mut() {
            const EMEM_SIZE: usize = 2 * LARGE_PAGE_SIZE + 64 * BASE_PAGE_SIZE;
            if frame.affinity == cur_affinity && frame.size() > EMEM_SIZE {
                // Let's make sure we have a frame that starts at a 2 MiB boundary which makes it easier
                // to populate the FrameCacheSmall
                let (low, large_page_aligned_frame) = frame.split_at_nearest_large_page_boundary();
                *frame = low;

                // Cut-away the top memory if the frame we got is too big
                let (emem, leftover_mem) = large_page_aligned_frame.split_at(EMEM_SIZE);
                if leftover_mem != Frame::empty() {
                    // And safe it for later processing
                    leftovers.push(leftover_mem);
                }

                gm.emem
                    .push(Mutex::new(mcache::FrameCacheSmall::new_with_frame(
                        cur_affinity,
                        emem,
                    )));

                cur_affinity += 1;
            }
        }
        // If this fails, memory is really fragmented or some nodes have no/little memory
        assert_eq!(
            gm.emem.len(),
            max_affinity,
            "Added early managers for all NUMA nodes"
        );

        // Construct an FrameCacheLarge for all nodes
        for affinity in 0..max_affinity {
            let mut ncache_memory = gm.emem[affinity].lock().allocate_large_page()?;
            let ncache_memory_addr: PAddr = ncache_memory.base;
            assert!(ncache_memory_addr != PAddr::zero());
            ncache_memory.zero(); // TODO(perf) this happens twice atm?

            let ncache_ptr = ncache_memory.uninitialized::<mcache::FrameCacheLarge>();

            let ncache: &'static mut mcache::FrameCacheLarge =
                mcache::FrameCacheLarge::init(ncache_ptr, affinity);
            debug_assert_eq!(
                &*ncache as *const _ as u64,
                paddr_to_kernel_vaddr(ncache_memory_addr).as_u64()
            );

            gm.node_caches.push(CachePadded::new(Mutex::new(ncache)));
        }

        // Populate the NCaches with all remaining memory
        // Ideally we fully exhaust all frames and put everything in the FrameCacheLarge
        for (ncache_affinity, ncache) in gm.node_caches.iter().enumerate() {
            let mut ncache_locked = ncache.lock();
            for frame in memory.iter() {
                if frame.affinity == ncache_affinity {
                    trace!("Trying to add {:?} frame to {:?}", frame, ncache_locked);
                    ncache_locked.populate_2m_first(*frame);
                }
            }
            for frame in leftovers.iter() {
                if frame.affinity == ncache_affinity {
                    trace!("Trying to add {:?} frame to {:?}", frame, ncache_locked);
                    ncache_locked.populate_2m_first(*frame);
                }
            }
        }

        Ok(gm)
    }
}

impl fmt::Debug for GlobalMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("GlobalMemory");

        for idx in 0..self.node_caches.len() {
            // TODO(correctness): rather than maybe run into a deadlock here
            // (e.g., if we are trying to print GlobalMemory when in a panic),
            // the relevant fields for printing Debug should probably
            // just be atomics
            let ncache = self.node_caches[idx].lock();
            f.field("FrameCacheLarge", &ncache);
        }

        f.finish()
    }
}
