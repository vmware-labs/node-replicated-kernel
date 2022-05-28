// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KCB is the local kernel control that stores all core local state.

use alloc::sync::Arc;
use core::cell::{RefCell, RefMut};
use core::fmt::Debug;

use arrayvec::ArrayVec;
use node_replication::Replica;
use slabmalloc::ZoneAllocator;
use spin::Lazy;

use crate::arch::kcb::init_kcb;
use crate::arch::MAX_NUMA_NODES;
use crate::error::KError;
use crate::memory::backends::{AllocatorStatistics, GrowBackend, PhysicalPageProvider};
use crate::memory::emem::EmergencyAllocator;
use crate::memory::global::GlobalMemory;
use crate::memory::mcache::TCache;
use crate::memory::mcache::TCacheSp;
use crate::nrproc::NrProcess;
use crate::process::{Process, MAX_PROCESSES};

pub(crate) use crate::arch::kcb::{get_kcb, try_get_kcb};

/// The core id of the current core (hardware thread).
#[thread_local]
pub(crate) static CORE_ID: Lazy<usize> =
    Lazy::new(|| atopology::MACHINE_TOPOLOGY.current_thread().id as usize);

/// The NUMA node id of the current core (hardware thread).
#[thread_local]
pub(crate) static NODE_ID: Lazy<usize> = Lazy::new(|| {
    atopology::MACHINE_TOPOLOGY
        .current_thread()
        .node_id
        .unwrap_or(0)
});

/// How many cores (hardware threads) we have per NUMA node.
pub(crate) static CORES_PER_NUMA_NODE: Lazy<usize> =
    Lazy::new(|| match atopology::MACHINE_TOPOLOGY.nodes().next() {
        Some(node) => node.threads().count(),
        None => 1,
    });

pub(crate) trait MemManager:
    PhysicalPageProvider + AllocatorStatistics + GrowBackend
{
}

/// State which allows to do memory management for a particular
/// NUMA node on a given core.
pub(crate) struct PhysicalMemoryArena {
    pub affinity: atopology::NodeId,

    /// A handle to the global memory manager.
    pub gmanager: Option<&'static GlobalMemory>,

    /// A handle to the per-core page-allocator.
    pub pmanager: Option<RefCell<TCache>>,

    /// A handle to the per-core ZoneAllocator.
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,
}

impl PhysicalMemoryArena {
    fn new(node: atopology::NodeId, global_memory: &'static GlobalMemory) -> Self {
        PhysicalMemoryArena {
            affinity: node,
            gmanager: Some(global_memory),
            pmanager: Some(RefCell::new(TCache::new(node))),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
        }
    }

    const fn uninit_with_node(node: atopology::NodeId) -> Self {
        PhysicalMemoryArena {
            affinity: node,
            gmanager: None,
            pmanager: None,
            zone_allocator: RefCell::new(ZoneAllocator::new()),
        }
    }
}

/// The Kernel Control Block for a given core.
/// It contains all core-local state of the kernel.
pub(crate) struct Kcb<A>
where
    A: ArchSpecificKcb,
    <<A as ArchSpecificKcb>::Process as crate::process::Process>::E: Debug + 'static,
{
    /// Architecture specific members of the KCB.
    pub arch: A,

    /// Are we in panic mode? Hopfully not.
    ///
    /// This can't be made a thread-local because we need it before we setup TLS
    /// (in dynamic memory allocation).
    ///
    /// # See also
    /// - `panic.rs`
    /// - `irq.rs`
    /// - `memory/mod.rs`
    pub in_panic_mode: bool,

    /// A handle to the early page-allocator.
    pub emanager: RefCell<TCacheSp>,

    /// A handle to a bump-style emergency Allocator.
    pub ezone_allocator: RefCell<EmergencyAllocator>,

    /// Related meta-data to manage physical memory for a given NUMA node.
    pub physical_memory: PhysicalMemoryArena,

    /// Related meta-data to manage persistent memory for a given NUMA node.
    pub pmem_memory: PhysicalMemoryArena,

    /// Contains a bunch of memory arenas, can be one for every NUMA node
    /// but we intialize it lazily upon calling `set_mem_affinity`.
    pub memory_arenas: [Option<PhysicalMemoryArena>; crate::arch::MAX_NUMA_NODES],

    /// Contains a bunch of pmem arenas, can be one for every NUMA node
    /// but we intialize it lazily upon calling `set_pmem_affinity`.
    pub pmem_arenas: [Option<PhysicalMemoryArena>; crate::arch::MAX_NUMA_NODES],
}

impl<A: ArchSpecificKcb> Kcb<A> {
    pub(crate) const fn new(emanager: TCacheSp, arch: A, node: atopology::NodeId) -> Kcb<A> {
        const DEFAULT_PHYSICAL_MEMORY_ARENA: Option<PhysicalMemoryArena> = None;
        Kcb {
            arch,
            in_panic_mode: false,
            emanager: RefCell::new(emanager),
            ezone_allocator: RefCell::new(EmergencyAllocator::empty()),
            memory_arenas: [DEFAULT_PHYSICAL_MEMORY_ARENA; MAX_NUMA_NODES],
            pmem_arenas: [DEFAULT_PHYSICAL_MEMORY_ARENA; MAX_NUMA_NODES],
            // Can't initialize these yet, we need basic Kcb first for
            // memory allocations (emanager):
            physical_memory: PhysicalMemoryArena::uninit_with_node(node),
            pmem_memory: PhysicalMemoryArena::uninit_with_node(node),
        }
    }

    pub(crate) fn set_panic_mode(&mut self) {
        self.in_panic_mode = true;
    }

    /// Ties this KCB to the local CPU by setting the KCB's GDT and IDT.
    pub(crate) fn install(&'static mut self) {
        self.arch.install();

        // Reloading gdt means we lost the content in `gs` so we
        // also set the kcb again using `wrgsbase`:
        init_kcb(self);
    }

    pub(crate) fn set_global_mem(&mut self, gm: &'static GlobalMemory) {
        self.physical_memory.gmanager = Some(gm);
    }

    pub(crate) fn set_global_pmem(&mut self, gm: &'static GlobalMemory) {
        self.pmem_memory.gmanager = Some(gm);
    }

    // Swaps out the current arena (from where we allocate memory) with a new
    // arena from the one that can get memory from the provided `node`. If no
    // arena for the current `node` exists, we create a new arena.
    fn swap_manager(
        gmanager: &'static GlobalMemory,
        current_arena: &mut PhysicalMemoryArena,
        arenas: &mut [Option<PhysicalMemoryArena>],
        node: atopology::NodeId,
    ) -> Result<(), KError> {
        if node < arenas.len() && node < atopology::MACHINE_TOPOLOGY.num_nodes() {
            if arenas[node].is_none() {
                arenas[node] = Some(PhysicalMemoryArena::new(node, gmanager));
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

    pub(crate) fn set_mem_affinity(&mut self, node: atopology::NodeId) -> Result<(), KError> {
        if node == self.physical_memory.affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }
        let gmanager = self
            .physical_memory
            .gmanager
            .ok_or(KError::GlobalMemoryNotSet)?;

        Kcb::<A>::swap_manager(
            gmanager,
            &mut self.physical_memory,
            &mut self.memory_arenas,
            node,
        )
    }

    pub(crate) fn set_pmem_affinity(&mut self, node: atopology::NodeId) -> Result<(), KError> {
        if node == self.pmem_memory.affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }
        let gmanager = self
            .pmem_memory
            .gmanager
            .ok_or(KError::GlobalMemoryNotSet)?;

        Kcb::<A>::swap_manager(gmanager, &mut self.pmem_memory, &mut self.pmem_arenas, node)
    }

    pub(crate) fn set_mem_manager(&mut self, pmanager: TCache) {
        self.physical_memory.pmanager = Some(RefCell::new(pmanager));
    }

    pub(crate) fn set_pmem_manager(&mut self, pmanager: TCache) {
        self.pmem_memory.pmanager = Some(RefCell::new(pmanager));
    }

    /// Get a reference to the early memory manager.
    pub(crate) fn emanager(&self) -> RefMut<TCacheSp> {
        self.emanager.borrow_mut()
    }

    /// Get a reference to the early memory manager.
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
        self.physical_memory.zone_allocator.try_borrow_mut()
    }

    /// Returns a reference to the core-local physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub(crate) fn mem_manager(&self) -> RefMut<dyn MemManager> {
        if core::intrinsics::unlikely(self.in_panic_mode) {
            return self.emanager();
        }

        self.physical_memory
            .pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }

    pub(crate) fn try_mem_manager(
        &self,
    ) -> Result<RefMut<dyn MemManager>, core::cell::BorrowMutError> {
        if core::intrinsics::unlikely(self.in_panic_mode) {
            return Ok(self.emanager());
        }

        self.physical_memory.pmanager.as_ref().map_or_else(
            || self.try_borrow_emanager(),
            |pmem| {
                pmem.try_borrow_mut()
                    .map(|rmt| RefMut::map(rmt, |t| t as &mut dyn MemManager))
            },
        )
    }

    pub(crate) fn pmem_manager(&self) -> RefMut<dyn MemManager> {
        self.pmem_memory
            .pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }
}

pub(crate) trait ArchSpecificKcb {
    type Process: Process + Sync;

    fn install(&mut self);

    #[allow(clippy::type_complexity)] // fix this once `associated_type_defaults` works
    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    >;
}
