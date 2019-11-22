//! KCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{RefCell, RefMut};

use slabmalloc::ZoneAllocator;

use crate::arch::kcb::init_kcb;
use crate::arch::KernelArgs;
use crate::memory::{tcache::TCache, vspace::AddressSpace, GlobalMemory};
use crate::process::Process;

pub use crate::arch::kcb::{get_kcb, try_get_kcb};

/// The Kernel Control Block for a given core.
/// It contains all core-local state of the kernel.
pub struct Kcb<A> {
    /// Architecture specific members of the KCB.
    pub arch: A,

    /// A pointer to the memory location of the kernel (ELF binary).
    kernel_binary: &'static [u8],

    /// A handle to the global memory manager.
    pub gmanager: Option<&'static GlobalMemory>,

    /// A handle to the early memory manager.
    pub emanager: RefCell<TCache>,

    /// A handle to the per-core page-allocator.
    pub pmanager: Option<RefCell<TCache>>,

    /// A handle to the per-core ZoneAllocator.
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,

    /// Which NUMA node this KCB / core belongs to
    pub node: topology::NodeId,

    /// Allocation affinity (which node we allocate from,
    /// this is a hack remove once custom allocators land).
    allocation_affinity: topology::NodeId,
}

impl<A: ArchSpecificKcb> Kcb<A> {
    pub fn new(
        kernel_binary: &'static [u8],
        emanager: TCache,
        arch: A,
        node: topology::NodeId,
    ) -> Kcb<A> {
        Kcb {
            arch,
            kernel_binary,
            emanager: RefCell::new(emanager),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
            node,
            allocation_affinity: 0,
            // Can't initialize these yet, needs basic Kcb first for
            // memory allocations:
            gmanager: None,
            pmanager: None,
        }
    }

    /// Ties this KCB to the local CPU by setting the KCB's GDT and IDT.
    pub fn install(&'static mut self) {
        self.arch.install();

        // Reloading gdt means we lost the content in `gs` so we
        // also set the kcb again using `wrgsbase`:
        init_kcb(self);
    }

    pub fn set_global_memory(&mut self, gm: &'static GlobalMemory) {
        self.gmanager = Some(gm);
    }

    pub fn set_allocation_affinity(&mut self, node: topology::NodeId) {
        self.allocation_affinity = node;
    }

    pub fn set_physical_memory_manager(&mut self, pmanager: TCache) {
        self.pmanager = Some(RefCell::new(pmanager));
    }

    /// Get a reference to the early memory manager.
    pub fn emanager(&self) -> RefMut<TCache> {
        self.emanager.borrow_mut()
    }

    /// Returns a reference to the core-local physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<TCache> {
        self.pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }

    pub fn try_mem_manager(&self) -> Result<RefMut<TCache>, core::cell::BorrowMutError> {
        self.pmanager
            .as_ref()
            .map_or(self.emanager.try_borrow_mut(), |pmem| pmem.try_borrow_mut())
    }

    pub fn kernel_binary(&self) -> &'static [u8] {
        self.kernel_binary
    }
}

pub trait ArchSpecificKcb {
    fn install(&mut self);
}
