// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! State that's used by a single core to handle dynamic memory allocations.

use core::cell::{RefCell, RefMut};
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use slabmalloc::ZoneAllocator;

use crate::arch::MAX_NUMA_NODES;
use crate::error::KError;
use crate::memory::Frame;
use crate::transport::shmem::SHMEM_AFFINITY;

use super::backends::MemManager;
use super::emem::EmergencyAllocator;
use super::global::GlobalMemory;
use super::mcache::FrameCacheEarly;
use super::mcache::FrameCacheSmall;

/// State with all "the right" memory managers to handle allocations on a given
/// core, during normal operations, for a particular `affinity` (NUMA node).
pub(crate) struct PerCoreAllocatorState {
    pub affinity: atopology::NodeId,

    /// A handle to the per-core page-allocator.
    pub pmanager: FrameCacheSmall,

    /// A handle to the per-core ZoneAllocator.
    pub zone_allocator: ZoneAllocator<'static>,
}

impl PerCoreAllocatorState {
    /// Create a new `PerCoreAllocatorState` for the given `affinity`.
    const fn new(node: atopology::NodeId) -> Self {
        PerCoreAllocatorState {
            affinity: node,
            pmanager: FrameCacheSmall::new(node),
            zone_allocator: ZoneAllocator::new(),
        }
    }

    pub(crate) fn new_with_frame(frame: Frame) -> Self {
        PerCoreAllocatorState {
            affinity: frame.affinity,
            pmanager: FrameCacheSmall::new_with_frame(frame.affinity, frame),
            zone_allocator: ZoneAllocator::new(),
        }
    }
}

/// The kernel state for dynamic memory allocation on a given core.
pub(crate) struct PerCoreMemory {
    /// Are we in panic mode? Hopfully not.
    ///
    /// This can't be made a thread-local because we need it before we setup TLS
    /// (in dynamic memory allocation).
    ///
    /// # See also
    /// - `panic.rs`
    /// - `irq.rs`
    /// - `memory/mod.rs`
    in_panic_mode: AtomicBool,

    /// A handle to the global memory manager.
    pub gmanager: Option<&'static GlobalMemory>,

    /// A handle to the global persistent memory manager.
    pub pgmanager: Option<&'static GlobalMemory>,

    /// A handle to the early page-allocator.
    pub emanager: RefCell<FrameCacheEarly>,

    /// A handle to a bump-style emergency Allocator.
    pub ezone_allocator: RefCell<EmergencyAllocator>,

    /// Related meta-data to manage physical memory for a given core.
    pub physical_memory: RefCell<PerCoreAllocatorState>,

    /// Related meta-data to manage persistent memory for a given core.
    pub persistent_memory: RefCell<PerCoreAllocatorState>,

    /// Contains a bunch of memory arenas with different affinities, in case a
    /// core needs to allocate memory from another NUMA node. Can have one for
    /// every NUMA node but we intialize it lazily upon calling
    /// `set_mem_affinity`.
    /// For a shmem arena, assume only one at index/affinity SHMEM_AFFINITY (which
    /// is assumed here to be MAX_NUMA_NODES) and initialized with `add_shmem_arena`
    pub memory_arenas: RefCell<[Option<PerCoreAllocatorState>; crate::arch::MAX_NUMA_NODES + 1]>,

    /// Contains a bunch of pmem arenas, in case a core needs to allocate mmeory
    /// from another NUMA node. Can have one for every NUMA node but we
    /// intialize it lazily upon calling `set_pmem_affinity`.
    pub pmem_arenas: RefCell<[Option<PerCoreAllocatorState>; crate::arch::MAX_NUMA_NODES]>,
}

impl PerCoreMemory {
    pub(crate) const fn new(emanager: FrameCacheEarly, node: atopology::NodeId) -> PerCoreMemory {
        const DEFAULT_PHYSICAL_MEMORY_ARENA: Option<PerCoreAllocatorState> = None;
        PerCoreMemory {
            in_panic_mode: AtomicBool::new(false),
            emanager: RefCell::new(emanager),
            gmanager: None,
            pgmanager: None,
            ezone_allocator: RefCell::new(EmergencyAllocator::empty()),
            memory_arenas: RefCell::new([DEFAULT_PHYSICAL_MEMORY_ARENA; MAX_NUMA_NODES + 1]),
            pmem_arenas: RefCell::new([DEFAULT_PHYSICAL_MEMORY_ARENA; MAX_NUMA_NODES]),
            physical_memory: RefCell::new(PerCoreAllocatorState::new(node)),
            persistent_memory: RefCell::new(PerCoreAllocatorState::new(node)),
        }
    }

    pub(super) fn use_emergency_allocator(&self) -> bool {
        self.in_panic_mode() || self.gmanager.is_none()
    }

    pub(crate) fn in_panic_mode(&self) -> bool {
        self.in_panic_mode.load(Ordering::Relaxed)
    }

    pub(crate) fn set_panic_mode(&self) {
        self.in_panic_mode.store(true, Ordering::Relaxed);
    }

    pub(crate) fn set_global_mem(&mut self, gm: &'static GlobalMemory) {
        self.gmanager = Some(gm);
    }

    pub(crate) fn set_global_pmem(&mut self, pgm: &'static GlobalMemory) {
        self.pgmanager = Some(pgm);
    }

    pub(crate) fn add_shmem_arena(&mut self, frame: Frame) -> Result<(), KError> {
        debug_assert!(frame.affinity == SHMEM_AFFINITY);
        let new_arena = PerCoreAllocatorState::new_with_frame(frame);
        PerCoreMemory::add_arena(
            new_arena,
            &mut *self.memory_arenas.borrow_mut(),
            SHMEM_AFFINITY,
        )
    }

    fn add_arena(
        new_arena: PerCoreAllocatorState,
        arenas: &mut [Option<PerCoreAllocatorState>],
        node: atopology::NodeId,
    ) -> Result<(), KError> {
        debug_assert!(new_arena.affinity == node);
        debug_assert!(node < arenas.len());
        debug_assert!(arenas[node].is_none());
        arenas[node].replace(new_arena);
        Ok(())
    }

    // Swaps out the current arena (from where we allocate memory) with a new
    // arena from the one that can get memory from the provided `node`. If no
    // arena for the current `node` exists, we create a new arena.
    fn swap_manager(
        current_arena: &mut PerCoreAllocatorState,
        arenas: &mut [Option<PerCoreAllocatorState>],
        node: atopology::NodeId,
    ) -> Result<(), KError> {
        if node < arenas.len()
            && (node < core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes())
                || node == SHMEM_AFFINITY)
        {
            if arenas[node].is_none() {
                if node == SHMEM_AFFINITY {
                    panic!("shmem arena cannot be initialized on the fly, instead call add_shmem_arena");
                }
                arenas[node] = Some(PerCoreAllocatorState::new(node));
            }
            debug_assert!(arenas[node].is_some());
            let mut arena = arenas[node].take().unwrap();
            debug_assert_eq!(arena.affinity, node);

            core::mem::swap(&mut arena, current_arena);
            arenas[arena.affinity as usize].replace(arena);

            Ok(())
        } else {
            Err(KError::InvalidAffinityId)
        }
    }

    pub(crate) fn set_mem_affinity(&self, node: atopology::NodeId) -> Result<(), KError> {
        if node == self.physical_memory.borrow().affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }
        PerCoreMemory::swap_manager(
            &mut self.physical_memory.borrow_mut(),
            &mut *self.memory_arenas.borrow_mut(),
            node,
        )
    }

    pub(crate) fn set_pmem_affinity(&self, node: atopology::NodeId) -> Result<(), KError> {
        if node == self.persistent_memory.borrow().affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }
        PerCoreMemory::swap_manager(
            &mut self.persistent_memory.borrow_mut(),
            &mut *self.pmem_arenas.borrow_mut(),
            node,
        )
    }

    /// Get a reference to the early memory manager.
    pub(crate) fn emanager(&self) -> RefMut<FrameCacheEarly> {
        self.emanager.borrow_mut()
    }

    /// Get a reference to the early memory manager.
    #[allow(unused)]
    fn try_borrow_emanager(&self) -> Result<RefMut<dyn MemManager>, core::cell::BorrowMutError> {
        self.emanager
            .try_borrow_mut()
            .map(|rmt| RefMut::map(rmt, |t| t as &mut dyn MemManager))
    }

    pub(crate) fn ezone_allocator(
        &self,
    ) -> Result<RefMut<impl slabmalloc::Allocator<'static>>, core::cell::BorrowMutError> {
        self.ezone_allocator.try_borrow_mut()
    }

    pub(crate) fn zone_allocator(
        &self,
    ) -> Result<RefMut<impl slabmalloc::Allocator<'static>>, core::cell::BorrowMutError> {
        Ok(RefMut::map(self.physical_memory.try_borrow_mut()?, |pm| {
            &mut pm.zone_allocator
        }))
    }

    /// Returns a reference to the core-local physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub(crate) fn mem_manager(&self) -> RefMut<dyn MemManager> {
        if core::intrinsics::unlikely(self.use_emergency_allocator()) {
            return self.emanager();
        }

        RefMut::map(self.physical_memory.borrow_mut(), |pm| &mut pm.pmanager)
    }

    pub(crate) fn try_mem_manager(
        &self,
    ) -> Result<RefMut<dyn MemManager>, core::cell::BorrowMutError> {
        if core::intrinsics::unlikely(self.use_emergency_allocator()) {
            return Ok(self.emanager());
        }

        Ok(RefMut::map(self.physical_memory.try_borrow_mut()?, |pm| {
            &mut pm.pmanager
        }))
    }

    pub(crate) fn try_allocator_state(
        &self,
    ) -> Result<RefMut<PerCoreAllocatorState>, core::cell::BorrowMutError> {
        self.physical_memory.try_borrow_mut()
    }

    pub(crate) fn pmem_manager(&self) -> RefMut<dyn MemManager> {
        RefMut::map(self.persistent_memory.borrow_mut(), |pm| &mut pm.pmanager)
    }
}

impl fmt::Debug for PerCoreMemory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PerCoreMemory")
            //.field("physical_memory", &self.physical_memory)
            //.field("persistent_memory", &self.persistent_memory)
            //.field("memory_arenas", &self.memory_arenas)
            //.field("pmem_arenas", &self.pmem_arenas)
            .field("emanager", &self.emanager)
            .field("ezone_allocator", &self.ezone_allocator)
            .field("in_panic_mode", &self.in_panic_mode)
            .finish()
    }
}
