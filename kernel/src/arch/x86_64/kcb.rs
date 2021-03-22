//! Arch specific data-structures and accessor functions for the
//! kernel control block.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::{RefCell, RefMut};
use core::pin::Pin;
use core::ptr;

use apic::x2apic::X2APICDriver;
use cnr::Replica as MlnrReplica;
use cnr::ReplicaToken as MlnrReplicaToken;
use x86::current::segmentation::{self};
use x86::current::task::TaskStateSegment;
use x86::msr::{wrmsr, IA32_KERNEL_GSBASE};

use crate::error::KError;
use crate::kcb::{ArchSpecificKcb, Kcb};
use crate::mlnr::MlnrKernelNode;

use crate::process::{Pid, ProcessError};
use crate::stack::{OwnedStack, Stack};

use super::gdt::GdtTable;
use super::irq::IdtTable;
use super::process::{Ring3Executor, Ring3Process};
use super::vspace::page_table::PageTable;
use super::KernelArgs;

/// Try to retrieve the KCB by reading the gs register.
///
/// This may return None if they KCB is not yet set
/// (i.e., during initialization).
pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb<Arch86Kcb>> {
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Kcb<Arch86Kcb>;
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
pub fn get_kcb<'a>() -> &'a mut Kcb<Arch86Kcb> {
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Kcb<Arch86Kcb>;
        assert!(kcb != ptr::null_mut(), "KCB not found in gs register.");
        let kptr = ptr::NonNull::new_unchecked(kcb);
        &mut *kptr.as_ptr()
    }
}

/// Installs the KCB by setting storing a pointer to it in the `gs`
/// register.
///
/// We also set IA32_KERNEL_GSBASE to the pointer to make sure
/// when we call `swapgs` on a syscall entry, we restore the pointer
/// to the KCB (user-space may change the `gs` register for
/// TLS etc.).
unsafe fn set_kcb<A: ArchSpecificKcb>(kcb: ptr::NonNull<Kcb<A>>) {
    // Set up the GS register to point to the KCB
    segmentation::wrgsbase(kcb.as_ptr() as u64);
    // Set up swapgs instruction to reset the gs register to the KCB on irq, trap or syscall
    wrmsr(IA32_KERNEL_GSBASE, kcb.as_ptr() as u64);
}

/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb<A: ArchSpecificKcb>(kcb: &mut Kcb<A>) {
    let kptr: ptr::NonNull<Kcb<A>> = ptr::NonNull::from(kcb);
    unsafe { set_kcb(kptr) };
}

/// Contains the arch-specific contents of the KCB.
#[repr(C)]
pub struct Arch86Kcb {
    /// Pointer to the syscall stack (this is )
    /// and should therefore always be at offset 0 of the Kcb struct!
    pub(crate) syscall_stack_top: *mut u8,

    /// Pointer to the save area of the core,
    /// this is referenced on trap/syscall entries to save the CPU state into it.
    ///
    /// State from the save_area may be copied into current_process` save area
    /// to handle upcalls (in the general state it is stored/resumed from here).
    pub save_area: Option<Pin<Box<kpi::arch::SaveArea>>>,

    /// A handle to the core-local interrupt driver.
    pub(crate) apic: RefCell<X2APICDriver>,

    /// A per-core GdtTable
    pub(crate) gdt: GdtTable,

    /// A per-core TSS (task-state)
    pub(crate) tss: TaskStateSegment,

    /// A per-core IDT (interrupt table)
    pub(crate) idt: IdtTable,

    /// Arguments passed to the kernel by the bootloader.
    kernel_args: &'static KernelArgs,

    /// A handle to the currently active (scheduled) process.
    current_process: Option<Arc<Ring3Executor>>,

    /// A handle to the initial kernel address space (created for us by the bootloader)
    /// It contains a 1:1 mapping of
    ///  * all physical memory (above `KERNEL_BASE`)
    ///  * IO APIC and local APIC memory (after initialization has completed)
    init_vspace: RefCell<PageTable>,

    ///
    pub mlnr_replica: Option<(Arc<MlnrReplica<'static, MlnrKernelNode>>, MlnrReplicaToken)>,

    /// Global id per hyperthread.
    id: usize,

    /// Max number of hyperthreads on the current socket.
    max_threads: usize,

    /// The interrupt stack (that is used by the CPU on interrupts/traps/faults)
    ///
    /// The CPU switches to this stack automatically for normal interrupts
    /// (see `set_interrupt_stacks`).
    /// This member should probably not be touched from normal code.
    interrupt_stack: Option<OwnedStack>,

    /// A reliable stack that is used for unrecoverable faults
    /// (double-fault, machine-check exception etc.)
    ///
    /// The CPU switches to this memory location automatically
    /// (see `set_interrupt_stacks`).
    /// This member should probably not be touched from normal code.
    unrecoverable_fault_stack: Option<OwnedStack>,

    /// A handle to the syscall stack memory location.
    ///
    /// We switch rsp/rbp to this stack in `exec.S`.
    /// This member should probably not be touched from normal code.
    syscall_stack: Option<OwnedStack>,
}

impl Arch86Kcb {
    pub(crate) fn new(
        kernel_args: &'static KernelArgs,
        apic: X2APICDriver,
        init_vspace: PageTable,
    ) -> Arch86Kcb {
        Arch86Kcb {
            kernel_args,
            syscall_stack_top: ptr::null_mut(),
            apic: RefCell::new(apic),
            gdt: Default::default(),
            tss: TaskStateSegment::new(),
            idt: Default::default(),
            // We don't have a process initially
            current_process: None,
            save_area: None,
            init_vspace: RefCell::new(init_vspace),
            interrupt_stack: None,
            syscall_stack: None,
            unrecoverable_fault_stack: None,
            mlnr_replica: None,
            id: 0,
            max_threads: 0,
        }
    }

    pub fn apic(&self) -> RefMut<X2APICDriver> {
        self.apic.borrow_mut()
    }

    pub fn init_vspace(&self) -> RefMut<PageTable> {
        self.init_vspace.borrow_mut()
    }

    pub fn setup_mlnr(
        &mut self,
        replica: Arc<MlnrReplica<'static, MlnrKernelNode>>,
        idx_token: MlnrReplicaToken,
    ) {
        let thread = topology::MACHINE_TOPOLOGY.current_thread();
        self.id = thread.id as usize;
        self.max_threads = match topology::MACHINE_TOPOLOGY.nodes().nth(0) {
            Some(node) => node.threads().count(),
            None => 1,
        };
        self.mlnr_replica = Some((replica, idx_token));
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn max_threads(&self) -> usize {
        self.max_threads
    }

    /// Swaps out current process with a new process. Returns the old process.
    pub fn swap_current_process(
        &mut self,
        new_current_process: Arc<Ring3Executor>,
    ) -> Option<Arc<Ring3Executor>> {
        self.current_process.replace(new_current_process)
    }

    pub fn has_current_process(&self) -> bool {
        self.current_process.is_some()
    }

    pub fn current_process(&self) -> Result<Arc<Ring3Executor>, ProcessError> {
        let p = self
            .current_process
            .as_ref()
            .ok_or(ProcessError::ProcessNotSet)?;
        Ok(p.clone())
    }

    pub fn set_interrupt_stacks(&mut self, ex_stack: OwnedStack, fault_stack: OwnedStack) {
        // Add the stack-top to the TSS so the CPU ends up switching
        // to this stack on an interrupt
        debug_assert_eq!(ex_stack.base() as u64 % 16, 0, "Stack not 16-byte aligned");
        self.tss.set_rsp(x86::Ring::Ring0, ex_stack.base() as u64);
        // Prepare ist[0] in tss for the double-fault stack
        debug_assert_eq!(
            fault_stack.base() as u64 % 16,
            0,
            "Stack not 16-byte aligned"
        );
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
        trace!("Syscall stack top set to: {:p}", self.syscall_stack_top);
        self.syscall_stack = Some(stack);

        // TODO: Would profit from a static assert and offsetof...
        debug_assert_eq!(
            (&self.syscall_stack_top as *const _ as usize) - (self as *const _ as usize),
            0,
            "syscall_stack_top should be at offset 0 (for assembly)"
        );
    }

    /// Install a CPU register save-area.
    ///
    /// Register are store here in case we get an interrupt/sytem call
    pub fn set_save_area(&mut self, save_area: Pin<Box<kpi::arch::SaveArea>>) {
        self.save_area = Some(save_area);
    }

    /// Get a pointer to the cores save-area.
    pub fn get_save_area_ptr(&self) -> *const kpi::arch::SaveArea {
        // TODO(unsafe): this probably doesn't need an unsafe, but I couldn't figure
        // out how to get that pointer out of the Option<Pin<Box>>>
        unsafe {
            core::mem::transmute::<_, *const kpi::arch::SaveArea>(
                &*(*self.save_area.as_ref().unwrap()),
            )
        }
    }

    pub fn kernel_args(&self) -> &'static KernelArgs {
        self.kernel_args
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
}

impl crate::kcb::ArchSpecificKcb for Arch86Kcb {
    type Process = Ring3Process;

    fn install(&mut self) {
        unsafe {
            // Switch to our new, core-local Gdt and Idt:
            self.gdt.install();
            self.idt.install();
        }
    }

    fn hwthread_id(&self) -> u64 {
        topology::MACHINE_TOPOLOGY.current_thread().id
    }
}

impl Kcb<Arch86Kcb> {
    pub fn current_pid(&self) -> Result<Pid, KError> {
        Ok(self.arch.current_process()?.pid)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn syscall_stack_top_offset() {
        let akcb: Arch86Kcb = unsafe { MaybeUninit::zeroed().assume_init() };
        assert_eq!(
            (&akcb.syscall_stack_top as *const _ as usize) - (&akcb as *const _ as usize),
            0,
            "The syscall_stack_top entry must be at offset 0 of KCB (referenced in assembly early on in exec.S)"
        );
    }

    #[test]
    fn save_area_offset() {
        let akcb: Arch86Kcb = unsafe { MaybeUninit::zeroed().assume_init() };
        assert_eq!(
            (&akcb.save_area as *const _ as usize) - (&akcb as *const _ as usize),
            8,
            "The save_area entry must be at offset 8 of KCB (for assembly code)"
        );
    }
}
