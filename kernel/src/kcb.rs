//! KCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{RefCell, RefMut};

use slabmalloc::ZoneAllocator;

use crate::arch::process::Process;
use crate::arch::vspace::VSpace;

use crate::arch::kcb::{init_kcb, ArchKcb};
use crate::arch::KernelArgs;

use crate::memory::{tcache::TCache, GlobalMemory};

pub use crate::arch::kcb::{get_kcb, try_get_kcb};

/// The Kernel Control Block for a given core.
/// It contains all core-local state of the kernel.
pub struct Kcb {
    /// Architecture specific members of the KCB.
    pub arch: ArchKcb,

    /// A handle to the currently active (scheduled) process.
    current_process: RefCell<Option<Box<Process>>>,

    /// Arguments passed to the kernel by the bootloader.
    kernel_args: &'static KernelArgs,

    /// A pointer to the memory location of the kernel (ELF binary).
    kernel_binary: &'static [u8],

    /// The initial VSpace as constructed by the bootloader.
    init_vspace: RefCell<VSpace>,

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

impl Kcb {
    pub fn new(
        kernel_args: &'static KernelArgs,
        kernel_binary: &'static [u8],
        init_vspace: VSpace,
        emanager: TCache,
        arch: ArchKcb,
        node: topology::NodeId,
    ) -> Kcb {
        Kcb {
            arch,
            kernel_args,
            kernel_binary,
            init_vspace: RefCell::new(init_vspace),
            emanager: RefCell::new(emanager),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
            // We don't have a process initially:
            current_process: RefCell::new(None),
            node,
            allocation_affinity: 0,
            // Can't initialize these yet, needs basic Kcb first for
            // memory allocations:
            gmanager: None,
            pmanager: None,
        }
    }

    /// Ties this KCB to the local CPU by setting the KCB's GDT and IDT.
    pub fn install(&mut self) {
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

    /// Swaps out current process with a new process. Returns the old process.
    pub fn swap_current_process(&self, new_current_process: Box<Process>) -> Option<Box<Process>> {
        let p = self.current_process.replace(Some(new_current_process));

        // TODO: need static assert and offsetof!
        /*debug_assert_eq!(
            (&self.arch.save_area as *const _ as usize) - (self as *const _ as usize),
            8,
            "The current process entry should be at offset 8 (for assembly)"
        );*/

        p
    }

    pub fn current_process(&self) -> RefMut<Option<Box<Process>>> {
        self.current_process.borrow_mut()
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

    pub fn init_vspace(&self) -> RefMut<VSpace> {
        self.init_vspace.borrow_mut()
    }

    pub fn kernel_binary(&self) -> &'static [u8] {
        self.kernel_binary
    }

    pub fn kernel_args(&self) -> &'static KernelArgs {
        self.kernel_args
    }
}
