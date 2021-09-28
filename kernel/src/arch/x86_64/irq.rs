// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Functionality to configure and deal with interrupts.
//!
//!
//! # Note on legacy support
//! We basically only support xAPIC mode, but we still receive e.g. serial
//! interrupts that are considered legacy. These have to be mapped to
//! GSI 0-15.
//!
//! From the ACPI specification:
//!
//! Systems that support both APIC and dual 8259 interrupt models must map globally
//! system interrupts 0-15 to the 8259 IRQs 0-15, except where Interrupt Source
//! Overrides are provided (see Section 5.2.12.5, “Interrupt Source Override
//! Structure”). This means that I/O APIC interrupt inputs 0-15 must be
//! mapped to global system interrupts 0-15 and have identical sources as the 8259
//! IRQs 0-15 unless overrides are used. This allows a platform to support OSPM
//! implementations that use the APIC model as well as OSPM implementations that
//! use the 8259 model (OSPM will only use one model; it will not mix models). When
//! OSPM supports the 8259 model, it will assume that all interrupt descriptors
//! reporting global system interrupts 0-15 correspond to 8259 IRQs. In the 8259
//! model all global system interrupts greater than 15 are ignored. If OSPM
//! implements APIC support, it will enable the APIC as described by the APIC
//! specification and will use all reported global system interrupts that fall
//! within the limits of the interrupt inputs defined by the I/O APIC structures.
//! For more information on hardware resource configuration see Section 6,
//! “Configuration.”
//!
//! # See also
//!  - 6.10 INTERRUPT DESCRIPTOR TABLE (IDT) in the Intel SDM vol. 3

#![allow(warnings)]

use core::fmt;

use alloc::boxed::Box;

use x86::bits64::segmentation::Descriptor64;
use x86::irq::*;
use x86::segmentation::{
    BuildDescriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
};
use x86::{dtables, Ring};

use apic::ApicDriver;
use klogger::{sprint, sprintln};
use log::{info, trace, warn};

use crate::kcb::ArchSpecificKcb;
use crate::memory::vspace::MapAction;
use crate::memory::Frame;
use crate::panic::{backtrace, backtrace_from};
use crate::process::{Executor, ResumeHandle};
use crate::{cnrfs, nr, nrproc, ExitReason};

use super::gdt::GdtTable;
use super::kcb::{get_kcb, Arch86Kcb};
use super::memory::{PAddr, VAddr, BASE_PAGE_SIZE, KERNEL_BASE};
use super::process::{Ring0Resumer, Ring3Process, Ring3Resumer};
use super::{debug, gdb, timer};

/// A macro to initialize an entry in an IDT table.
///
/// This maks sure we have an external C declaration to the symbol
/// in `isr.S` that is the entry point for the given interrupt `num`
/// then continues to store a descriptor for it in the `idt_table`.
///
/// Everything is declared as interrupt gates for now. Trap and Interrupt gates are similar,
/// and their descriptors are structurally the same, they differ only in the "type" field.
/// The difference is that for interrupt gates, interrupts are automatically disabled upon entry
/// and re-enabled upon IRET which restores the saved RFLAGS.
///
/// In our code we currently don't use IRET but rather SYSRET and we reset the RFLAGs manually.
///
/// # Note
/// See also `isr.S`
macro_rules! idt_set {
    ($idt_table:expr, $num:expr, $f:ident, $ist:expr) => {{
        extern "C" {
            #[no_mangle]
            fn $f();
        }

        // We are changing to the kernel code segment in ring 0:
        let seg = SegmentSelector::new(GdtTable::CS_KERNEL_INDEX as u16, Ring::Ring0);

        // Build an interrupt descriptor that switches to
        // `f`, which points to external assembly functions like `isr_handlerX`.
        //
        // `dpl` is set to Ring3 so we allow interrupts from everywhere.
        //
        // $ist is normally set to 0, which means we use the interrupt_stack from the kcb.
        // $ist is set to 1 for double-faults and other severe exceptions
        // to use the `unrecoverable_fault_stack` from the kcb
        // and 2 for debug exception to use the `debug_stack` from the kcb.
        $idt_table[$num as usize] = DescriptorBuilder::interrupt_descriptor(seg, $f as u64)
            .dpl(Ring::Ring3)
            .ist($ist)
            .present()
            .finish();
    }};
}

/// The IDT entry for handling the TLB work-queue
pub const TLB_WORK_PENDING: u8 = 251;
/// The IDT entry for handling GC in cnr.
pub const MLNR_GC_INIT: u8 = 250;

/// The IDT table can hold a maximum of 256 entries.
pub const IDT_SIZE: usize = 256;

/// The IDT table that is installed early on during initialization.
///
/// Later on each core is free to use their own IDT table
/// or can remain using the `DEFAULT_IDT` since the `DEFAULT_IDT` does not contain
/// any per-core shared state.
static mut DEFAULT_IDT: IdtTable = IdtTable([Descriptor64::NULL; IDT_SIZE]);

/// A wrapper type to represent the array of IDT entries
pub struct IdtTable([Descriptor64; IDT_SIZE]);

/// The default for an IdtTable.
impl Default for IdtTable {
    /// Initializes the given IdtTable by populating it with external
    /// IRQ handler functions as declared by `isr.S`.
    fn default() -> Self {
        // Our IdtTable starts out with 256 'NULL' descriptors
        let mut table = IdtTable([Descriptor64::NULL; IDT_SIZE]);

        idt_set!(table.0, DIVIDE_ERROR_VECTOR, isr_handler0, 0);
        idt_set!(table.0, DEBUG_VECTOR, isr_handler1, 2);
        idt_set!(table.0, NONMASKABLE_INTERRUPT_VECTOR, isr_handler2, 0);
        idt_set!(table.0, BREAKPOINT_VECTOR, isr_handler3, 0);
        idt_set!(table.0, OVERFLOW_VECTOR, isr_handler4, 0);
        idt_set!(table.0, BOUND_RANGE_EXCEEDED_VECTOR, isr_handler5, 0);
        idt_set!(table.0, INVALID_OPCODE_VECTOR, isr_handler6, 0);
        idt_set!(table.0, DEVICE_NOT_AVAILABLE_VECTOR, isr_handler7, 0);
        // For double-faults, we use the
        // _early handler to abort in any case:
        idt_set!(table.0, DOUBLE_FAULT_VECTOR, isr_handler_early8, 1);
        idt_set!(table.0, COPROCESSOR_SEGMENT_OVERRUN_VECTOR, isr_handler9, 0);
        idt_set!(table.0, INVALID_TSS_VECTOR, isr_handler10, 0);
        idt_set!(table.0, SEGMENT_NOT_PRESENT_VECTOR, isr_handler11, 0);
        idt_set!(table.0, STACK_SEGEMENT_FAULT_VECTOR, isr_handler12, 0);
        idt_set!(table.0, GENERAL_PROTECTION_FAULT_VECTOR, isr_handler13, 0);
        idt_set!(table.0, PAGE_FAULT_VECTOR, isr_handler14, 0);

        idt_set!(table.0, X87_FPU_VECTOR, isr_handler16, 0);
        idt_set!(table.0, ALIGNMENT_CHECK_VECTOR, isr_handler17, 0);
        // For machine-check exceptions, we use the
        // _early handler to abort in any case:
        idt_set!(table.0, MACHINE_CHECK_VECTOR, isr_handler_early18, 1);
        idt_set!(table.0, SIMD_FLOATING_POINT_VECTOR, isr_handler19, 0);
        idt_set!(table.0, VIRTUALIZATION_VECTOR, isr_handler20, 0);
        idt_set!(table.0, 30, isr_handler30, 0);

        // PIC interrupts:
        idt_set!(table.0, 32, isr_handler32, 0);
        idt_set!(table.0, 33, isr_handler33, 0);
        idt_set!(table.0, 34, isr_handler34, 0);
        idt_set!(table.0, 35, isr_handler35, 0);
        idt_set!(table.0, 36, isr_handler36, 0);
        idt_set!(table.0, 37, isr_handler37, 0);
        idt_set!(table.0, 38, isr_handler38, 0);
        idt_set!(table.0, 39, isr_handler39, 0);
        idt_set!(table.0, 40, isr_handler40, 0);
        idt_set!(table.0, 41, isr_handler41, 0);
        idt_set!(table.0, 42, isr_handler42, 0);
        idt_set!(table.0, 43, isr_handler43, 0);
        idt_set!(table.0, 44, isr_handler44, 0);
        idt_set!(table.0, 45, isr_handler45, 0);
        idt_set!(table.0, 46, isr_handler46, 0);
        idt_set!(table.0, 47, isr_handler47, 0);

        idt_set!(table.0, TLB_WORK_PENDING as usize, isr_handler251, 0);
        idt_set!(table.0, MLNR_GC_INIT as usize, isr_handler250, 0);
        idt_set!(table.0, apic::TSC_TIMER_VECTOR as usize, isr_handler252, 0);

        table
    }
}

impl IdtTable {
    /// Create a very simple IDT table that always ends up in
    /// `handle_generic_exception_early` which then aborts.
    fn early() -> IdtTable {
        let mut table = IdtTable([Descriptor64::NULL; IDT_SIZE]);

        idt_set!(table.0, DIVIDE_ERROR_VECTOR, isr_handler_early0, 0);
        idt_set!(table.0, DEBUG_VECTOR, isr_handler_early1, 2);
        idt_set!(table.0, NONMASKABLE_INTERRUPT_VECTOR, isr_handler_early2, 0);
        idt_set!(table.0, BREAKPOINT_VECTOR, isr_handler_early3, 0);
        idt_set!(table.0, OVERFLOW_VECTOR, isr_handler_early4, 0);
        idt_set!(table.0, BOUND_RANGE_EXCEEDED_VECTOR, isr_handler_early5, 0);
        idt_set!(table.0, INVALID_OPCODE_VECTOR, isr_handler_early6, 0);
        idt_set!(table.0, DEVICE_NOT_AVAILABLE_VECTOR, isr_handler_early7, 0);
        // For double-faults, we use the
        // _early handler to abort in any case:
        idt_set!(table.0, DOUBLE_FAULT_VECTOR, isr_handler_early8, 1);
        idt_set!(
            table.0,
            COPROCESSOR_SEGMENT_OVERRUN_VECTOR,
            isr_handler_early9,
            0
        );
        idt_set!(table.0, INVALID_TSS_VECTOR, isr_handler_early10, 0);
        idt_set!(table.0, SEGMENT_NOT_PRESENT_VECTOR, isr_handler_early11, 0);
        idt_set!(table.0, STACK_SEGEMENT_FAULT_VECTOR, isr_handler_early12, 0);
        idt_set!(
            table.0,
            GENERAL_PROTECTION_FAULT_VECTOR,
            isr_handler_early13,
            0
        );
        idt_set!(table.0, PAGE_FAULT_VECTOR, isr_handler_early14, 0);

        idt_set!(table.0, X87_FPU_VECTOR, isr_handler_early16, 0);
        idt_set!(table.0, ALIGNMENT_CHECK_VECTOR, isr_handler_early17, 0);
        // For machine-check exceptions, we use the
        // _early handler to abort in any case:
        idt_set!(table.0, MACHINE_CHECK_VECTOR, isr_handler_early18, 1);
        idt_set!(table.0, SIMD_FLOATING_POINT_VECTOR, isr_handler_early19, 0);
        idt_set!(table.0, VIRTUALIZATION_VECTOR, isr_handler_early20, 0);

        idt_set!(table.0, TLB_WORK_PENDING as usize, isr_handler_early251, 0);

        idt_set!(table.0, MLNR_GC_INIT as usize, isr_handler_early250, 0);
        idt_set!(
            table.0,
            apic::TSC_TIMER_VECTOR as usize,
            isr_handler_early252,
            0
        );

        table
    }

    /// Install the IdtTable in the current core.
    pub unsafe fn install(&self) {
        let idtptr = dtables::DescriptorTablePointer::new_from_slice(&self.0);
        dtables::lidt(&idtptr);
        trace!("IDT set to {:p}", &idtptr);
    }
}

/// Initializes and loads the early IDT into the CPU.
///
/// With this done we should be able to catch basic pfaults and gpfaults.
pub unsafe fn setup_early_idt() {
    DEFAULT_IDT = IdtTable::early();
    DEFAULT_IDT.install();
    trace!("Early IDT table initialized.");
}

/// Arguments as provided by the ISR generic call handler (see `isr.S`).
///
/// Since we store this struct on the entry of an IRQ make sure it's a
/// multiple of 16-bytes so the stack stays aligned.
///
/// # See also
/// Described in Intel SDM 3a, Figure 6-8. IA-32e Mode Stack Usage After Privilege Level Change
#[repr(C, packed)]
pub struct ExceptionArguments {
    _reserved: u64,
    vector: u64,
    exception: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

impl fmt::Debug for ExceptionArguments {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            write!(
                f,
                "ExceptionArguments {{ vec = 0x{:x} exception = 0x{:x} rip = 0x{:x}, cs = 0x{:x} rflags = 0x{:x} rsp = 0x{:x} ss = 0x{:x} }}",
                self.vector, self.exception, self.rip, self.cs, self.rflags, self.rsp, self.ss
            )
        }
    }
}

/// Handler for a vector that we're not expecting.
///
/// TODO: Right now we terminate kernel.
/// Should log error and resume.
unsafe fn unhandled_irq(a: &ExceptionArguments) {
    sprint!("\n[IRQ] UNHANDLED:");
    if a.vector < 16 {
        let desc = &EXCEPTIONS[a.vector as usize];
        sprintln!(" {}", desc);
    } else {
        sprintln!(" dev vector {}", a.vector);
    }
    sprintln!("{:?}", a);
    backtrace();

    let kcb = get_kcb();
    sprintln!("Register State:\n{:?}", kcb.arch.save_area);

    if !kcb.in_panic_mode {
        kcb.arch.save_area.as_ref().map(|sa| {
            backtrace_from(sa.rbp, sa.rsp, sa.rip);
        });
    }

    debug::shutdown(ExitReason::UnhandledInterrupt);
}

/// Handler for unexpected page-faults.
///
/// TODO: Right now we terminate kernel.
/// Should abort process and resume.
unsafe fn pf_handler(a: &ExceptionArguments) {
    use crate::arch::kcb;

    let err = PageFaultError::from_bits_truncate(a.exception as u32);
    let faulting_address = x86::controlregs::cr2();
    let kcb = get_kcb();

    // If this is a user-mode page-fault make sure it's not a spurious
    // page-fault by not having a replica in-sync with others
    if err.contains(PageFaultError::US) {
        let faulting_address_va = VAddr::from(faulting_address);
        let pid = kcb
            .current_pid()
            .expect("A pid must be set in this if branch (US bit set in page-fault error)");

        match nrproc::NrProcess::<Ring3Process>::resolve(pid, faulting_address_va) {
            Ok((paddr, rights)) => {
                // TODO(harden): We probably want to warn/abort if we get many
                // "spurious" pfaults for the same addr in quick succession: one
                // bug I encountered is when I accidentially made executor
                // objects with the PML4 base address of the same process but
                // from another replica, in that case it will end up pfaulting
                // here until the other replica (by chance) advances and this
                // code doesn't really do anything...
                trace!(
                    "Spurious page-fault, after resolve page-table is up to date {} {} -> {:#x} {:#b} on {}",
                    pid, faulting_address_va, paddr, rights, kcb.arch.hwthread_id()
                );
                let r = kcb_iret_handle(kcb);
                r.resume()
            }
            Err(_) => {
                // unresolved page-fault, proceed with abort below
            }
        }
    }

    sprintln!("[IRQ] Page Fault on {}", kcb.arch.id());
    sprintln!("{}", err);

    // Enable user-space access
    x86::current::rflags::stac();

    for i in 0..32 {
        let ptr = (a.rsp as *const u64).offset(i);
        sprintln!("stack[{}] = {:#x}", i, *ptr);
    }

    // Print where the fault happend in the address-space:
    let faulting_address = x86::controlregs::cr2();
    sprint!("Faulting address: {:#x}", faulting_address);
    sprint!(" Instruction Pointer: {:#x}", a.rip);

    /*
    if !err.contains(PageFaultError::US) {
        kcb::try_get_kcb().map(|k| {
            sprintln!(
                " (in ELF: {:#x})",
                faulting_address - k.kernel_args().kernel_elf_offset.as_usize()
            )
        });
    } else {
        sprintln!("");
    }
    */

    // Print the RIP that triggered the fault:
    sprint!("Instruction Pointer: {:#x}", a.rip);
    if !err.contains(PageFaultError::US) {
        kcb::try_get_kcb().map(|k| {
            sprintln!(
                " (in ELF: {:#x})",
                a.rip - k.arch.kernel_args().kernel_elf_offset.as_u64()
            )
        });
    } else {
        sprintln!("");
    }

    sprintln!("{:?}", a);
    let kcb = get_kcb();
    sprintln!("Register State:\n{:?}", kcb.arch.save_area);
    if !kcb.in_panic_mode {
        kcb.arch.save_area.as_ref().map(|sa| {
            backtrace_from(sa.rbp, sa.rsp, sa.rip);
        });
    }

    debug::shutdown(ExitReason::PageFault);
}

/// Handler for a debug exception.
///
/// The default behavior right now is just to print a warning and resume
/// execution in user-space.
unsafe fn dbg_handler(a: &ExceptionArguments) {
    let desc = &EXCEPTIONS[a.vector as usize];
    warn!("Got debug interrupt {}", desc.source);

    let kcb = get_kcb();
    if kcb.arch.has_executor() {
        let r = Ring3Resumer::new_restore(kcb.arch.get_save_area_ptr());
        r.resume()
    } else {
        gdb::event_loop(None);
        let r = Ring0Resumer::new_iret(kcb.arch.get_save_area_ptr());
        r.resume()
    }
}

/// Handler for the timer exception.
///
/// We currently use it to periodically make sure that a replica
/// makes forward progress to avoid liveness issues.
unsafe fn timer_handler(a: &ExceptionArguments) {
    #[cfg(feature = "test-timer")]
    {
        // Don't change this print stmt. without changing
        // `s01_timer` in integration-tests.rs:
        sprintln!("Got a timer interrupt");
        debug::shutdown(ExitReason::Ok);
    }

    // Periodically advance replica state, then resume immediately
    nr::KernelNode::synchronize();
    let kcb = get_kcb();
    for pid in 0..crate::process::MAX_PROCESSES {
        nrproc::NrProcess::<Ring3Process>::synchronize(pid);
    }

    if kcb.arch.has_executor() {
        // TODO(process-mgmt): Ensures that we still periodically
        // check and advance replicas even on cores that have a core.
        // Only a single idle core per replica should probably do that,
        // so if cores go properly back to idling when finished execution,
        // this is no longer necessary...
        let is_replica_main_thread = {
            let thread = atopology::MACHINE_TOPOLOGY.current_thread();
            thread.node().is_none()
                || thread
                    .node()
                    .unwrap()
                    .threads()
                    .next()
                    .map(|t| t.id == thread.id)
                    .unwrap_or(false)
        };
        if is_replica_main_thread {
            timer::set(timer::DEFAULT_TIMER_DEADLINE);
        }

        // Return immediately
        let r = kcb_iret_handle(kcb);
        r.resume()
    } else {
        // Go to scheduler instead
        //warn!("got a timer on core {}", kcb.arch.id());
        crate::scheduler::schedule()
    }
}

/// Handler for a general protection exception.
///
/// TODO: Right now we terminate kernel.
/// Should abort process and resume.
unsafe fn gp_handler(a: &ExceptionArguments) {
    let desc = &EXCEPTIONS[a.vector as usize];
    sprint!("\n[IRQ] GENERAL PROTECTION FAULT: ");
    sprintln!("From {}", desc.source);

    // Enable user-space access
    x86::current::rflags::stac();

    if a.exception > 0 {
        sprintln!(
            "Error value: {:?}",
            SegmentSelector::from_raw(a.exception as u16)
        );
    } else {
        sprintln!("No error!");
    }

    // Print the RIP that triggered the fault:
    //use crate::arch::kcb;
    sprint!("Instruction Pointer: {:#x}", a.rip);
    /*kcb::try_get_kcb::<Arch86Kcb>().map(|k| {
        sprintln!(
            " (in ELF: {:#x})",
            a.rip - k.kernel_args().kernel_elf_offset.as_u64()
        )
    });*/

    sprintln!("{:?}", a);
    let kcb = get_kcb();
    sprintln!("Register State:\n{:?}", kcb.arch.save_area);

    for i in 0..12 {
        let ptr = (a.rsp as *const u64).offset(i);
        sprintln!("stack[{}] = {:#x}", i, *ptr);
    }

    if !kcb.in_panic_mode {
        kcb.arch.save_area.as_ref().map(|sa| {
            backtrace_from(sa.rbp, sa.rsp, sa.rip);
        });
    }

    debug::shutdown(ExitReason::GeneralProtectionFault);
}

fn kcb_resume_handle(kcb: &crate::kcb::Kcb<Arch86Kcb>) -> Ring3Resumer {
    Ring3Resumer::new_restore(kcb.arch.get_save_area_ptr())
}

fn kcb_iret_handle(kcb: &crate::kcb::Kcb<Arch86Kcb>) -> Ring3Resumer {
    Ring3Resumer::new_iret(kcb.arch.get_save_area_ptr())
}

/// Handler for all exceptions that happen early during the initialization
/// (i.e., before we have a KCB) or are unrecoverable errors.
///
/// For these execptions we use different assembly bootstrap wrappers
/// that don't assume `gs` has a KCB reference
/// or save the context (because we don't have a KCB yet).
///
/// The only thing this is used for is to report as much as possible, and
/// then exit.
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_generic_exception_early(a: ExceptionArguments) -> ! {
    sprintln!("[IRQ] Got an exception during kernel initialization:");
    //sprintln!("{:?}", a);

    match a.vector as u8 {
        GENERAL_PROTECTION_FAULT_VECTOR => {
            // Don't change the next line without changing the `gpfault_early` test:
            sprintln!("[IRQ] Early General Protection Fault");
            debug::shutdown(ExitReason::ExceptionDuringInitialization);
        }
        PAGE_FAULT_VECTOR => {
            // Don't change the next line without changing the `pfault_early` test:
            sprintln!("[IRQ] Early Page Fault");
            let err = PageFaultError::from_bits_truncate(a.exception as u32);
            sprintln!("{}", err);
            let fault_addr = unsafe { x86::controlregs::cr2() };
            // Don't change the next line without changing the `pfault_early` test:
            sprintln!("Faulting address: {:#x}", fault_addr);
            debug::shutdown(ExitReason::ExceptionDuringInitialization);
        }
        DOUBLE_FAULT_VECTOR => {
            #[cfg(feature = "test-double-fault")]
            debug::assert_being_on_fault_stack();

            // Don't change the next line without changing the `double_fault` test:
            sprintln!("[IRQ] Double Fault");
            debug::shutdown(ExitReason::UnrecoverableError);
        }
        MACHINE_CHECK_VECTOR => {
            sprintln!("[IRQ] Machine Check Exception");
            debug::shutdown(ExitReason::UnrecoverableError);
        }
        0..=31 => {
            sprintln!("[IRQ] Early Unexpected Exception");
            let desc = &EXCEPTIONS[a.vector as usize];
            sprintln!("{}", desc);
            debug::shutdown(ExitReason::ExceptionDuringInitialization);
        }
        x => {
            sprintln!("[IRQ] Early Unexpected Device Interrupt: {}", x);
            debug::shutdown(ExitReason::ExceptionDuringInitialization);
        }
    };
}

/// Rust entry point for exception handling (see isr.S).
/// TODO: does this need to be extern?
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_generic_exception(a: ExceptionArguments) -> ! {
    unsafe {
        let start = x86::time::rdtsc();
        assert!(a.vector < 256);
        trace!("handle_generic_exception {:?}", a);
        acknowledge();

        let kcb = get_kcb();

        // If we have an active process we should do scheduler activations:
        // TODO(scheduling): do proper masking based on some VCPU mask
        // TODO(scheduling): Currently don't deliver interrupts to process not currently running
        if a.vector > 30 && a.vector < 250 || a.vector == BREAKPOINT_VECTOR.into() {
            trace!("handle_generic_exception {:?}", a);

            let mut plock = kcb.arch.current_executor();
            let p = plock.as_mut().unwrap();

            let resumer = {
                let was_disabled = {
                    trace!("vcpu state is: pc_disabled {:?}", p.vcpu().pc_disabled);
                    let was_disabled = p.vcpu().upcalls_disabled(VAddr::from(a.rip));
                    p.vcpu().disable_upcalls();
                    was_disabled
                };

                if was_disabled {
                    // Resume to the current save area...
                    warn!("Upcalling while disabled");
                    kcb_resume_handle(kcb)
                } else {
                    // Copy CURRENT_SAVE_AREA to process enabled save area
                    // then resume in the upcall handler
                    kcb.arch.save_area.as_ref().map(|sa| {
                        p.vcpu().enabled_state = **sa;
                    });

                    p.upcall(a.vector, a.exception)
                }
            };

            trace!("resuming now...");
            drop(plock);

            resumer.resume()
        } // make sure we drop the KCB object here

        // Shortcut to handle protection and page faults
        if a.vector == GENERAL_PROTECTION_FAULT_VECTOR.into() {
            gp_handler(&a);
        } else if a.vector == PAGE_FAULT_VECTOR.into() {
            pf_handler(&a);
        } else if a.vector == DEBUG_VECTOR.into() {
            dbg_handler(&a);
        } else if a.vector == BREAKPOINT_VECTOR.into() {
            dbg_handler(&a);
        } else if a.vector == TLB_WORK_PENDING.into() {
            let kcb = get_kcb();
            trace!("got an interrupt {:?}", kcb.arch.id());
            super::tlb::dequeue(kcb.arch.id());

            if kcb.arch.has_executor() {
                // Return immediately
                kcb.tlb_time += x86::time::rdtsc() - start;
                kcb_iret_handle(kcb).resume()
            } else {
                // Go to scheduler instead
                crate::scheduler::schedule()
            }
        } else if a.vector == MLNR_GC_INIT.into() {
            // nr::KernelNode::synchronize(); /* TODO: Do we need this?
            super::tlb::dequeue(kcb.arch.id());

            let kcb = get_kcb();
            if kcb.arch.has_executor() {
                kcb_iret_handle(kcb).resume()
            } else {
                loop {
                    super::tlb::eager_advance_fs_replica();

                    // Reset a timer and sleep for some time
                    timer::set(timer::DEFAULT_TIMER_DEADLINE);
                    for _i in 0..1200 {
                        core::sync::atomic::spin_loop_hint();
                    }
                }
            }
        } else if a.vector == apic::TSC_TIMER_VECTOR.into() {
            timer_handler(&a);
        }

        unhandled_irq(&a);
    }

    unreachable!("Should not come here")
}

/// Registers a handler IRQ handler function.
pub unsafe fn register_handler(
    vector: usize,
    _handler: Box<dyn Fn(&ExceptionArguments) -> () + Send + 'static>,
) {
    if vector > IDT_SIZE - 1 {
        debug!("Invalid vector!");
        return;
    }

    info!("register irq handler for vector {}", vector);
    //let mut handlers = IRQ_HANDLERS.lock();
    //handlers[vector] = handler;
}

/// Initialize IO APICs by enumerating them
/// and making sure the device registers are mapped
/// in the kernel-space.
pub fn ioapic_initialize() {
    let ioapic_len = atopology::MACHINE_TOPOLOGY.io_apics().count();
    /*crate::memory::KernelAllocator::try_refill_tcache(4 * ioapic_len, 0)
    .expect("Refill didn't work");*/

    let kcb = get_kcb();

    for io_apic in atopology::MACHINE_TOPOLOGY.io_apics() {
        info!("Initialize IO APIC {:?}", io_apic);

        let paddr = PAddr::from(io_apic.address as u64);
        let ioapic_frame = Frame::new(paddr, BASE_PAGE_SIZE, 0);
        let vbase = PAddr::from(KERNEL_BASE);
        kcb.arch
            .init_vspace()
            .map_identity_with_offset(
                vbase,
                ioapic_frame.base,
                ioapic_frame.size(),
                MapAction::ReadWriteKernel,
            )
            .expect("Can't create APIC mapping?");
    }
}

/// Establishes a route for a GSI on the IOAPIC.
///
/// # TODO
/// Currently this just enables everything and routes it to
/// core 0. This is because, we should probably just support MSI(X)
/// and don't invest a lot in legacy interrupts...
pub fn ioapic_establish_route(_gsi: u64, _core: u64) {
    use crate::memory::vspace::MapAction;
    use crate::memory::{paddr_to_kernel_vaddr, PAddr};

    for io_apic in atopology::MACHINE_TOPOLOGY.io_apics() {
        let addr = PAddr::from(io_apic.address as u64);

        let mut inst =
            unsafe { x86::apic::ioapic::IoApic::new(paddr_to_kernel_vaddr(addr).as_usize()) };
        trace!(
            "This IOAPIC supports {} Interrupts",
            inst.supported_interrupts()
        );

        for i in 0..inst.supported_interrupts() {
            let gsi = io_apic.global_irq_base + i as u32;
            if gsi < 16 {
                trace!(
                    "Enable irq {} which maps to GSI#{}",
                    i,
                    io_apic.global_irq_base + i as u32
                );
                if i != 2 && i != 1 {
                    inst.enable(i, 0);
                }
            }
        }
    }
}

fn acknowledge() {
    let kcb = get_kcb();
    let mut apic = kcb.arch.apic();
    apic.eoi();
}

pub fn enable() {
    unsafe {
        x86::irq::enable();
    }
}

pub fn disable() {
    unsafe {
        x86::irq::disable();
    }
}
