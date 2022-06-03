// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Arch specific data-structures and accessor functions for the
//! kernel control block.

use alloc::boxed::Box;
use core::pin::Pin;
use core::ptr;

use log::trace;
use x86::current::segmentation;
use x86::current::task::TaskStateSegment;
use x86::msr::{wrmsr, IA32_KERNEL_GSBASE};

use crate::memory::per_core::PerCoreMemory;
use crate::stack::{OwnedStack, Stack};

use super::gdt::GdtTable;
use super::irq::IdtTable;

/// "Dereferences" the fs register at `offset`.
///
/// # Safety
/// - Offset needs to be within valid memory for whatever the gs register points
///   to.
macro_rules! gs_deref {
    ($offset:expr) => {{
        let gs: u64;
        core::arch::asm!("movq %gs:{offset}, {result}",
                offset = const ($offset),
                result = out(reg) gs,
                options(att_syntax)
        );
        gs
    }};
}

/// Try to retrieve the per-core memory allocator by reading the gs register.
///
/// This may return None if the memory allocators is not yet set (i.e., during
/// initialization).
///
/// # Safety
/// - The fsgsbase bit must be enabled.
/// - This gets a handle to PerCoreMemory (ideally, we should ensure that there
///   is no outstanding mut alias to it e.g., during initialization see comments
///   in mod.rs)
pub(crate) fn try_per_core_mem() -> Option<&'static PerCoreMemory> {
    unsafe {
        if segmentation::rdgsbase() != 0x0 {
            let pcm = gs_deref!(memoffset::offset_of!(Arch86Kcb, mem)) as *const PerCoreMemory;
            if pcm != ptr::null_mut() {
                let static_pcm = &*pcm as &'static PerCoreMemory;
                //log::info!("Found per-core memory at {:?}", static_pcm);
                return Some(static_pcm);
            }
        }
    }
    None
}

/// Reference to per-core memory state.
///
/// Must only call this after initialization has completed. So basically ok to
/// call in everywhere in the kernel except care must be taken in `arch`,
/// `crate::memory` and some places in `arch::irq`.
///
/// # Panics
/// - If the per-core memory is not yet initialized (only in debug mode).
pub(crate) fn per_core_mem() -> &'static PerCoreMemory {
    // Safety:
    // - Either this will be initialized with PerCoreMemory or panic.
    // - rdgsbase is ok because we enabled the instruction during core init
    // - [`Arch86Kcb::initialize_gs`] made sure that the gs has the right object
    //   / layout for the cast
    // - There should be no mut alias to the per-core memory after init is
    //   complete (this would basically be a #[thread_local] in a regular
    //   program)
    // - And we check/panic that the gs register is not null
    unsafe {
        debug_assert!(segmentation::rdgsbase() != 0x0, "gs not yet initialized");
        (&*(gs_deref!(memoffset::offset_of!(Arch86Kcb, mem)) as *const PerCoreMemory))
            as &'static PerCoreMemory
    }
}

/// Retrieve the Arch86Kcb by reading the gs register.
///
/// # Panic
/// This will fail in case the KCB is not yet set (i.e., early on during
/// initialization).
pub(crate) fn get_kcb<'a>() -> &'a mut Arch86Kcb {
    // TODO(safety): not safe should return a non-mut reference with mutable
    // stuff wrapped in RefCell or similar (treat the same as a thread-local)
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Arch86Kcb;
        assert!(kcb != ptr::null_mut(), "KCB not found in gs register.");
        let kptr = ptr::NonNull::new_unchecked(kcb);
        &mut *kptr.as_ptr()
    }
}

/// Architecture specific core control block.
///
/// Contains the arch-specific hardware state of a given x86 core.
/// `repr(C)` because assembly code references entries of this struct.
#[repr(C)]
pub(crate) struct Arch86Kcb {
    /// Pointer to the syscall stack (this is referenced in assembly) and should
    /// therefore always remain at offset 0 of the Kcb struct!
    pub(super) syscall_stack_top: *mut u8,

    /// Pointer to the save area of the core, this is referenced on trap/syscall
    /// entries to save the CPU state into it and therefore has to remain at
    /// offset 0x8 in this struct.
    ///
    /// State from the save_area may be copied into the `current_executor` save
    /// area to handle upcalls (in the general state it is stored/resumed from
    /// here).
    pub(super) save_area: Option<Pin<Box<kpi::arch::SaveArea>>>,

    /// The memory location of the TLS (`fs` base) region.
    pub(super) tls_base: *const super::tls::ThreadControlBlock,

    /// The state of the memory allocator on this core.
    pub(crate) mem: &'static PerCoreMemory,

    /// A per-core GdtTable
    pub(super) gdt: GdtTable,

    /// A per-core TSS (task-state)
    pub(super) tss: TaskStateSegment,

    /// A per-core IDT (interrupt table)
    pub(super) idt: IdtTable,

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

    /// A debug stack that is used for for debug exceptions
    /// (int 0x1, breakpoints, watchpoints etc.)
    ///
    /// Ensures we can inspect old stack with GDB.
    ///
    /// The CPU switches to this memory location automatically
    /// (see `set_interrupt_stacks`).
    /// This member should probably not be touched from normal code.
    debug_stack: Option<OwnedStack>,

    /// A handle to the syscall stack memory location.
    ///
    /// We switch rsp/rbp to this stack in `exec.S`.
    /// This member should probably not be touched from normal code.
    syscall_stack: Option<OwnedStack>,
}
// The `syscall_stack_top` entry must be at offset 0 of KCB (for assembly code in exec.S, isr.S & process.rs)
static_assertions::const_assert_eq!(memoffset::offset_of!(Arch86Kcb, syscall_stack_top), 0);
// The `save_area` entry must be at offset 8 of KCB (for assembly code in exec.S, isr.S & process.rs)
static_assertions::const_assert_eq!(memoffset::offset_of!(Arch86Kcb, save_area), 8);
// The `tls_area` entry must be at offset 16 of KCB (for assembly code in exec.S, isr.S & process.rs)
static_assertions::const_assert_eq!(memoffset::offset_of!(Arch86Kcb, tls_base), 16);

impl Arch86Kcb {
    pub(crate) fn new(mem: &'static PerCoreMemory) -> Arch86Kcb {
        Arch86Kcb {
            syscall_stack_top: ptr::null_mut(),
            tls_base: ptr::null(),
            mem,
            gdt: Default::default(),
            tss: TaskStateSegment::new(),
            idt: Default::default(),
            save_area: None,
            interrupt_stack: None,
            syscall_stack: None,
            unrecoverable_fault_stack: None,
            debug_stack: None,
        }
    }

    pub(crate) fn set_interrupt_stacks(
        &mut self,
        ex_stack: OwnedStack,
        fault_stack: OwnedStack,
        debug_stack: OwnedStack,
    ) {
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

        debug_assert_eq!(
            debug_stack.base() as u64 % 16,
            0,
            "Stack not 16-byte aligned"
        );
        self.tss.set_ist(1, debug_stack.base() as u64);

        // Link TSS in Gdt
        // It's important to only construct the GdtTable
        // after we did `set_rsp` on the TSS, otherwise
        // interrupts won't work.
        self.gdt = GdtTable::new(&self.tss);

        self.interrupt_stack = Some(ex_stack);
        self.unrecoverable_fault_stack = Some(fault_stack);
    }

    pub(crate) fn set_syscall_stack(&mut self, stack: OwnedStack) {
        self.syscall_stack_top = stack.base();
        trace!("Syscall stack top set to: {:p}", self.syscall_stack_top);
        self.syscall_stack = Some(stack);
    }

    /// Install a CPU register save-area.
    ///
    /// Register are store here in case we get an interrupt/sytem call
    pub(crate) fn set_save_area(&mut self, save_area: Pin<Box<kpi::arch::SaveArea>>) {
        self.save_area = Some(save_area);
    }

    /// Get a pointer to the cores save-area.
    pub(crate) fn get_save_area_ptr(&self) -> *const kpi::arch::SaveArea {
        // TODO(unsafe): this probably doesn't need an unsafe, but I couldn't figure
        // out how to get that pointer out of the Option<Pin<Box>>>
        unsafe {
            core::mem::transmute::<_, *const kpi::arch::SaveArea>(
                &*(*self.save_area.as_ref().unwrap()),
            )
        }
    }

    #[cfg(all(feature = "integration-test", feature = "test-double-fault"))]
    pub(crate) fn fault_stack_range(&self) -> (u64, u64) {
        (
            self.unrecoverable_fault_stack
                .as_ref()
                .map_or(0, |s| s.limit() as u64),
            self.unrecoverable_fault_stack
                .as_ref()
                .map_or(0, |s| s.base() as u64),
        )
    }

    pub(super) fn install(&mut self) {
        unsafe {
            // Switch to our new, core-local Gdt and Idt:
            self.gdt.install();
            self.idt.install();
            // gdt install will reload/reset gs/fs segments.
            self.initialize_gs();
        }
    }

    /// Initialize the KCB by making sure the `gs` register points to it.
    ///
    /// # Safety
    /// - This will overwrite the `gs` register which should point to the
    ///   valid-core local data.
    /// - Ideally this function should only be called twice on each core:
    ///   1. Early on once we have a not quite fully initialized KCB (to get
    ///      basic memory allocation working
    ///   2. Later on, once we have a fully initialized KCB and want to change
    ///      the GDT/IDT tables and therefore we have to reload the `gs`
    ///      register. This is taken care of by the [`ArchX86Kcb::install`]
    ///      function.
    pub(super) unsafe fn initialize_gs(&mut self) {
        /// Installs the KCB by setting storing a pointer to it in the `gs`
        /// register.
        ///
        /// We also set IA32_KERNEL_GSBASE to the pointer to make sure
        /// when we call `swapgs` on a syscall entry, we restore the pointer
        /// to the KCB (user-space may change the `gs` register for
        /// TLS etc.).
        unsafe fn set_kcb(kcb: ptr::NonNull<Arch86Kcb>) {
            // Set up the GS register to point to the KCB
            segmentation::wrgsbase(kcb.as_ptr() as u64);
            // Set up swapgs instruction to reset the gs register to the KCB on irq, trap or syscall
            wrmsr(IA32_KERNEL_GSBASE, kcb.as_ptr() as u64);
        }

        let kptr: ptr::NonNull<Arch86Kcb> = ptr::NonNull::from(self);
        set_kcb(kptr)
    }
}
