// KCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{Ref, RefCell, RefMut};
use core::pin::Pin;
use core::ptr;

use apic::xapic::XAPICDriver;
use x86::current::segmentation::{self, Descriptor64};
use x86::current::task::TaskStateSegment;
use x86::msr::{wrmsr, IA32_KERNEL_GSBASE};

use super::gdt::GdtTable;
use super::irq::IdtTable;
use super::process::Process;
use super::vspace::VSpace;

use crate::arch::{KernelArgs, Module};
use crate::memory::buddy::BuddyFrameAllocator;
use crate::memory::emem::EarlyPhysicalManager;
use crate::memory::PhysicalAllocator;
use crate::stack::{OwnedStack, Stack};

/// Try to retrieve the KCB by reading the gs register.
pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb> {
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Kcb;
        if kcb != ptr::null_mut() {
            let kptr = ptr::NonNull::new_unchecked(kcb);
            Some(&mut *kptr.as_ptr())
        } else {
            None
        }
    }
}

/// Retrieve the KCB by reading the gs register.
///
/// # Panic
/// This will fail in case the KCB is not yet set (i.e., early on during
/// initialization).
pub fn get_kcb<'a>() -> &'a mut Kcb {
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Kcb;
        assert!(kcb != ptr::null_mut(), "KCB not found in gs register.");
        let kptr = ptr::NonNull::new_unchecked(kcb);
        &mut *kptr.as_ptr()
    }
}

/// Installs the KCB by setting the gs register to point to it.
///
/// We also set IA32_KERNEL_GSBASE to the kcb pointer to make sure
/// when we call swapgs on a syscall entry, we restore the pointer
/// to the KCB (since user-space may change gs register for
/// TLS etc.).
unsafe fn set_kcb(kcb: ptr::NonNull<Kcb>) {
    // Set up the GS register to point to the KCB
    segmentation::wrgsbase(kcb.as_ptr() as u64);
    // Set up swapgs instruction to reset the gs register to the KCB on irq, trap or syscall
    wrmsr(IA32_KERNEL_GSBASE, kcb.as_ptr() as u64);
}

/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb(kcb: &mut Kcb) {
    let kptr: ptr::NonNull<Kcb> = ptr::NonNull::from(kcb);
    unsafe { set_kcb(kptr) };
}

/// The Kernel Control Block for a given core. It contains all core-local state of the kernel.
pub struct Kcb {
    /// Pointer to the syscall stack (this is referenced in assembly early on in exec.S)
    /// and should therefore always be at offset 0 of the Kcb struct!
    syscall_stack_top: *mut u8,

    /// Pointer to the save area of the core,
    /// this is referenced on trap/syscall entries to save the CPU state into it.
    ///
    /// State from the save_area may be copied into current_process` save area
    /// to handle upcalls (in the general state it is stored/resumed from here).
    pub save_area: Option<Pin<Box<kpi::arch::SaveArea>>>,

    /// A handle to the currently active (scheduled) process.
    current_process: RefCell<Option<Box<Process>>>,

    /// Arguments passed to the kernel by the bootloader.
    kernel_args: &'static KernelArgs<[Module; 2]>,

    /// A pointer to the memory location of the kernel ELF binary.
    kernel_binary: &'static [u8],

    /// The initial VSpace as constructed by the bootloader.
    init_vspace: RefCell<VSpace>,

    /// A handle to the core-local interrupt driver.
    apic: RefCell<XAPICDriver>,

    /// A per-core GdtTable
    gdt: GdtTable,

    /// A per-core TSS (task-state)
    tss: TaskStateSegment,

    /// A per-core IDT (interrupt table)
    idt: IdtTable,

    /// A handle to the physical memory manager.
    pmanager: Option<RefCell<BuddyFrameAllocator>>,

    /// A handle to the early memory manager.
    emanager: RefCell<EarlyPhysicalManager>,

    /// The interrupt stack (that is used by the CPU on interrupts/traps/faults)
    ///
    /// The CPU switches to this memory location automatically for normal interrupts
    /// (see `set_interrupt_stacks`).
    /// This member should probably not be touched from normal code.
    interrupt_stack: Option<OwnedStack>,

    /// A reliable stack that is used for unrecoverable faults only
    /// (double-fault, machine-check exception etc.)
    ///
    /// The CPU switches to this memory location automatically
    /// (see `set_interrupt_stacks`).
    /// This member should probably not be touched from normal code.
    unrecoverable_fault_stack: Option<OwnedStack>,

    /// A handle to the syscall stack memory location.
    ///
    /// We switch rsp/rbp to point in here in exec.S.
    /// This member should probably not be touched from normal code.
    syscall_stack: Option<OwnedStack>,
}

impl Kcb {
    pub fn new(
        kernel_args: &'static KernelArgs<[Module; 2]>,
        kernel_binary: &'static [u8],
        init_vspace: VSpace,
        emanager: EarlyPhysicalManager,
        apic: XAPICDriver,
    ) -> Kcb {
        Kcb {
            syscall_stack_top: ptr::null_mut(),
            kernel_args: kernel_args,
            kernel_binary: kernel_binary,
            init_vspace: RefCell::new(init_vspace),
            emanager: RefCell::new(emanager),
            apic: RefCell::new(apic),
            gdt: Default::default(),
            tss: TaskStateSegment::new(),
            idt: Default::default(),
            // Can't initialize these yet, needs Kcb for memory allocations:
            pmanager: None,
            save_area: None,
            interrupt_stack: None,
            syscall_stack: None,
            unrecoverable_fault_stack: None,
            // We don't have a process initially:
            current_process: RefCell::new(None),
        }
    }

    /// Ties this KCB to the local CPU by setting the KCB's GDT and IDT.
    pub fn install(&mut self) {
        unsafe {
            // Switch to our new, core-local Gdt and Idt:
            self.gdt.install();
            self.idt.install();
        }

        // Reloading gdt means we lost the content in `gs` so we
        // also set the kcb again using `wrgsbase`:
        init_kcb(self);
    }

    pub fn set_physical_memory_manager(&mut self, pmanager: BuddyFrameAllocator) {
        self.pmanager = Some(RefCell::new(pmanager));
    }

    pub fn set_interrupt_stacks(&mut self, ex_stack: OwnedStack, fault_stack: OwnedStack) {
        // Add the stack-top to the TSS so the CPU ends up switching
        // to this stack on an interrupt
        self.tss.set_rsp(x86::Ring::Ring0, ex_stack.base() as u64);
        // Prepare ist[0] in tss for the double-fault stack
        self.tss.set_ist(0, fault_stack.base() as u64);

        // Link TSS in Gdt
        // It's important to only construct the GdtTable
        // after we did `set_rsp` on the TSS, otherwise
        // interrupts won't work.
        self.gdt = GdtTable::new(&self.tss);

        self.interrupt_stack = Some(ex_stack);
        self.unrecoverable_fault_stack = Some(fault_stack);
    }

    pub fn set_syscall_stack(&mut self, stack: OwnedStack) {
        self.syscall_stack_top = stack.base();
        debug!("Syscall stack top set to: {:p}", self.syscall_stack_top);
        self.syscall_stack = Some(stack);

        // TODO: Would profit from a static assert and offsetof...
        debug_assert_eq!(
            (&self.syscall_stack_top as *const _ as usize) - (self as *const _ as usize),
            0,
            "syscall_stack_top should be at offset 0 (for assembly)"
        );
    }

    /// Set the core' save-area
    ///
    /// Register are store here in case we get an interrupt/ssytem call
    pub fn set_save_area(&mut self, save_area: Pin<Box<kpi::arch::SaveArea>>) {
        self.save_area = Some(save_area);
    }

    /// Get a pointer to the cores save-area.
    pub fn get_save_area_ptr(&self) -> *const kpi::arch::SaveArea {
        // TODO: this probably doesn't need an unsafe, but I couldn't figure
        // out how to get that pointer out of the Option<Pin<Box>>>
        unsafe {
            core::mem::transmute::<_, *const kpi::arch::SaveArea>(
                &*(*self.save_area.as_ref().unwrap()),
            )
        }
    }

    /// Swaps out current process with a new process. Returns the old process.
    pub fn swap_current_process(&self, new_current_process: Box<Process>) -> Option<Box<Process>> {
        let p = self.current_process.replace(Some(new_current_process));

        // TODO: need static assert and offsetof!
        debug_assert_eq!(
            (&self.save_area as *const _ as usize) - (self as *const _ as usize),
            8,
            "The current process entry should be at offset 8 (for assembly)"
        );

        p
    }

    #[cfg(feature = "test-double-fault")]
    pub fn fault_stack_range(&self) -> (u64, u64) {
        (
            self.unrecoverable_fault_stack
                .as_ref()
                .map_or(0, |s| s.limit() as u64),
            self.unrecoverable_fault_stack
                .as_ref()
                .map_or(0, |s| s.base() as u64),
        )
    }

    pub fn current_process(&self) -> RefMut<Option<Box<Process>>> {
        self.current_process.borrow_mut()
    }

    /// Get a reference to the early memory manager.
    pub fn emanager(&self) -> RefMut<EarlyPhysicalManager> {
        self.emanager.borrow_mut()
    }

    /// Returns a reference to the core-local physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<dyn PhysicalAllocator> {
        self.pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }

    /// Returns a reference to the zone manager (that manges all memory for the local)
    /// numa node.
    pub fn zone_manager() {}

    pub fn apic(&self) -> RefMut<XAPICDriver> {
        self.apic.borrow_mut()
    }

    pub fn init_vspace(&self) -> RefMut<VSpace> {
        self.init_vspace.borrow_mut()
    }

    pub fn kernel_binary(&self) -> &'static [u8] {
        self.kernel_binary
    }

    pub fn kernel_args(&self) -> &'static KernelArgs<[Module; 2]> {
        self.kernel_args
    }
}
