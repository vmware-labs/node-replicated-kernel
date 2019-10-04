//! Functionality to configure and deal with interrupts.
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

use core::fmt;

use alloc::boxed::Box;
use alloc::vec::Vec;

use x86::apic::ApicControl;
use x86::bits64::paging::VAddr;
use x86::bits64::segmentation::Descriptor64;
use x86::dtables;
use x86::irq;
use x86::segmentation::{
    BuildDescriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
};
use x86::Ring;

use log::debug;
use spin::Mutex;

use crate::panic::{backtrace, backtrace_from};
use crate::ExitReason;

use super::debug;
use super::kcb::get_kcb;
use super::process::ResumeHandle;

/// A macro to initialize an entry in an IDT table.
///
/// This maks sure we have an external C declaration to the symbol
/// in `isr.S` that is the entry point for the given interrupt `num`
/// then continues to store a descriptor for it in the `idt_table`.
///
/// # Note
/// See also `isr.S`
macro_rules! idt_set {
    ($idt_table:expr, $num:expr, $f:ident, $sel:expr, $flags:expr) => {{
        extern "C" {
            #[no_mangle]
            fn $f();
        }

        $idt_table[$num] = DescriptorBuilder::interrupt_descriptor($sel, $f as u64)
            .dpl(Ring::Ring3)
            .present()
            .finish();
    }};
}

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
    /// IRQ handler functions declares in `isr.S`.
    ///
    /// # Notes
    /// Everything is declared as interrupt gates for now. Trap and Interrupt gates are similar,
    /// and their descriptors are structurally the same, they differ only in the "type" field.
    /// The difference is that for interrupt gates, interrupts are automatically disabled upon entry
    /// and re-enabled upon IRET which restores the saved RFLAGS.
    ///
    /// In our code we currently don't  use IRET but rather SYSRET and we reset the RFLAGs manually.
    fn default() -> Self {
        debug!("Install IRQ handler");

        let mut table = IdtTable([Descriptor64::NULL; IDT_SIZE]);

        let seg = SegmentSelector::new(1, Ring::Ring0);
        idt_set!(table.0, 0, isr_handler0, seg, 0x8E);
        idt_set!(table.0, 1, isr_handler1, seg, 0x8E);
        idt_set!(table.0, 2, isr_handler2, seg, 0x8E);
        idt_set!(table.0, 3, isr_handler3, seg, 0x8E);
        idt_set!(table.0, 4, isr_handler4, seg, 0x8E);
        idt_set!(table.0, 5, isr_handler5, seg, 0x8E);
        idt_set!(table.0, 6, isr_handler6, seg, 0x8E);
        idt_set!(table.0, 7, isr_handler7, seg, 0x8E);
        idt_set!(table.0, 8, isr_handler8, seg, 0x8E);
        idt_set!(table.0, 9, isr_handler9, seg, 0x8E);
        idt_set!(table.0, 10, isr_handler10, seg, 0x8E);
        idt_set!(table.0, 11, isr_handler11, seg, 0x8E);
        idt_set!(table.0, 12, isr_handler12, seg, 0x8E);
        idt_set!(table.0, 13, isr_handler13, seg, 0x8E);
        idt_set!(table.0, 14, isr_handler14, seg, 0x8E);
        idt_set!(table.0, 15, isr_handler15, seg, 0x8E);

        idt_set!(table.0, 32, isr_handler32, seg, 0x8E);
        idt_set!(table.0, 33, isr_handler33, seg, 0x8E);
        idt_set!(table.0, 34, isr_handler34, seg, 0x8E);
        idt_set!(table.0, 35, isr_handler35, seg, 0x8E);
        idt_set!(table.0, 36, isr_handler36, seg, 0x8E);
        idt_set!(table.0, 37, isr_handler37, seg, 0x8E);
        idt_set!(table.0, 38, isr_handler38, seg, 0x8E);
        idt_set!(table.0, 39, isr_handler39, seg, 0x8E);
        idt_set!(table.0, 40, isr_handler40, seg, 0x8E);
        idt_set!(table.0, 41, isr_handler41, seg, 0x8E);
        idt_set!(table.0, 42, isr_handler42, seg, 0x8E);
        idt_set!(table.0, 43, isr_handler43, seg, 0x8E);
        idt_set!(table.0, 44, isr_handler44, seg, 0x8E);
        idt_set!(table.0, 45, isr_handler45, seg, 0x8E);
        idt_set!(table.0, 46, isr_handler46, seg, 0x8E);
        idt_set!(table.0, 47, isr_handler47, seg, 0x8E);

        table
    }
}

impl IdtTable {
    /// Create a new IdtTable (with default entries).
    fn new() -> IdtTable {
        Default::default()
    }

    /// Install the IdtTable in the current core.
    unsafe fn install(&self) {
        let idtptr = dtables::DescriptorTablePointer::new_from_slice(&self.0);
        dtables::lidt(&idtptr);
        trace!("IDT set to {:p}", &idtptr);
    }
}

/// Initializes and loads the IDT into the CPU.
///
/// With this done we should be able to catch basic pfaults and gpfaults.
pub unsafe fn setup_early_idt() {
    DEFAULT_IDT = IdtTable::new();
    DEFAULT_IDT.install();
    trace!("IDT table initialized.");
}

lazy_static! {
    static ref IRQ_HANDLERS: Mutex<Vec<Box<dyn Fn(&ExceptionArguments) -> () + Send + 'static>>> = {
        let mut vec: Vec<Box<dyn Fn(&ExceptionArguments) -> () + Send + 'static>> =
            Vec::with_capacity(IDT_SIZE);
        for _ in 0..IDT_SIZE {
            vec.push(Box::new(|e| unsafe { unhandled_irq(e) }));
        }
        Mutex::new(vec)
    };
}

unsafe fn unhandled_irq(a: &ExceptionArguments) {
    sprint!("\n[IRQ] UNHANDLED:");
    if a.vector < 16 {
        let desc = &irq::EXCEPTIONS[a.vector as usize];
        sprintln!(" {}", desc);
    } else {
        sprintln!(" dev vector {}", a.vector);
    }
    sprintln!("{:?}", a);
    backtrace();
    let kcb = get_kcb();
    sprintln!("Register State:\n{:?}", kcb.save_area);
    kcb.save_area.as_ref().map(|sa| {
        backtrace_from(sa.rbp, sa.rsp, sa.rip);
    });

    debug::shutdown(ExitReason::UnhandledInterrupt);
}

unsafe fn pf_handler(a: &ExceptionArguments) {
    use x86::irq::PageFaultError;
    sprintln!("[IRQ] Page Fault");
    let err = PageFaultError::from_bits_truncate(a.exception as u32);
    sprintln!("{}", err);

    // Enable user-space access to do backtraces in user-space
    x86::current::rflags::stac();

    for i in 0..12 {
        let ptr = (a.rsp as *const u64).offset(i);
        sprintln!("stack[{}] = {:#x}", i, *ptr);
    }

    // Print where the fault happend in the address-space:
    let faulting_address = x86::controlregs::cr2();
    sprint!("Faulting address: {:#x}", faulting_address);
    sprint!(" Instruction Pointer: {:#x}", a.rip);
    use crate::arch::kcb;

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
                a.rip - k.kernel_args().kernel_elf_offset.as_u64()
            )
        });
    } else {
        sprintln!("");
    }

    sprintln!("{:?}", a);
    let kcb = get_kcb();
    sprintln!("Register State:\n{:?}", kcb.save_area);

    kcb.save_area.as_ref().map(|sa| {
        backtrace_from(sa.rbp, sa.rsp, sa.rip);
    });

    debug::shutdown(ExitReason::PageFault);
}

unsafe fn dbg_handler(a: &ExceptionArguments) {
    let desc = &irq::EXCEPTIONS[a.vector as usize];
    warn!("Got debug interrupt {}", desc.source);

    let kcb = crate::kcb::get_kcb();
    let r = ResumeHandle::new_restore(kcb.get_save_area_ptr());
    r.resume()
}

unsafe fn gp_handler(a: &ExceptionArguments) {
    let desc = &irq::EXCEPTIONS[a.vector as usize];
    sprint!("\n[IRQ] GENERAL PROTECTION FAULT: ");
    sprintln!("From {}", desc.source);

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
    /*kcb::try_get_kcb().map(|k| {
        sprintln!(
            " (in ELF: {:#x})",
            a.rip - k.kernel_args().kernel_elf_offset.as_u64()
        )
    });*/

    sprintln!("{:?}", a);
    let kcb = get_kcb();
    sprintln!("Register State:\n{:?}", kcb.save_area);
    kcb.save_area.as_ref().map(|sa| {
        backtrace_from(sa.rbp, sa.rsp, sa.rip);
    });

    debug::shutdown(ExitReason::GeneralProtectionFault);
}

/// Arguments as provided by the ISR generic call handler (see isr.S).
/// Described in Intel SDM 3a, Figure 6-8. IA-32e Mode Stack Usage After Privilege Level Change
#[repr(C, packed)]
pub struct ExceptionArguments {
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

fn kcb_resume_handle(kcb: &crate::kcb::Kcb) -> ResumeHandle {
    ResumeHandle::new_restore(kcb.get_save_area_ptr())
}

/// Rust entry point for exception handling (see isr.S).
/// TODO: does this need to be extern?
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_generic_exception(a: ExceptionArguments) -> ! {
    unsafe {
        assert!(a.vector < 256);
        trace!("handle_generic_exception {:?}", a);
        acknowledge();

        // If we have an active process we should do scheduler
        // activations:
        // TODO: do proper masking based on some VCPU mask...
        if a.vector > 30 || a.vector == 3 {
            trace!("handle_generic_exception {:?}", a);

            let kcb = crate::kcb::get_kcb();
            let mut plock = kcb.current_process();
            let p = plock.as_mut().unwrap();

            let resumer = {
                let was_disabled = p.vcpu_ctl.as_mut().map_or(true, |vcpu| {
                    trace!(
                        "vcpu state is: pc_disabled {:?} is_disabled {:?}",
                        vcpu.pc_disabled,
                        vcpu.is_disabled
                    );
                    let was_disabled = vcpu.upcalls_disabled(VAddr::from(0x0));
                    vcpu.disable_upcalls();
                    was_disabled
                });

                if was_disabled {
                    // Resume to the current save area...
                    warn!("Upcalling while disabled");
                    kcb_resume_handle(kcb)
                } else {
                    // Copy CURRENT_SAVE_AREA to process enabled save area
                    // then resume in the upcall handler
                    let _was_disabled = p.vcpu_ctl.as_mut().map(|vcpu| {
                        kcb.save_area.as_ref().map(|sa| {
                            vcpu.enabled_state = **sa;
                        });
                    });

                    p.upcall(a.vector, a.exception)
                }
            };

            trace!("resuming now...");
            drop(plock);

            resumer.resume()
        } // make sure we drop the KCB object here

        // Shortcut to handle protection and page faults
        // that lock and IRQ_HANDLERS thing requires a bit
        // too much machinery and is only set-up late in initialization
        // and unfortunately! sometimes things break early on...
        if a.vector == 0xd {
            gp_handler(&a);
        } else if a.vector == 0xe {
            pf_handler(&a);
        } else if a.vector == 0x3 {
            dbg_handler(&a);
        }

        info!("handle_generic_exception {:?}", a);
        let vec_handlers = IRQ_HANDLERS.lock();
        (*vec_handlers)[a.vector as usize](&a);
    }

    unreachable!("Should not come here")
}

pub unsafe fn acknowledge() {
    let kcb = crate::kcb::get_kcb();
    let mut apic = kcb.apic();
    apic.eoi();
}

/// Registers a handler IRQ handler function.
pub unsafe fn register_handler(
    vector: usize,
    handler: Box<dyn Fn(&ExceptionArguments) -> () + Send + 'static>,
) {
    if vector > IDT_SIZE - 1 {
        debug!("Invalid vector!");
        return;
    }

    info!("register irq handler for vector {}", vector);
    let mut handlers = IRQ_HANDLERS.lock();
    handlers[vector] = handler;
}

/// Finishes the initialization of IRQ handlers once we have memory allocation.
pub fn init_irq_handlers() {
    lazy_static::initialize(&IRQ_HANDLERS);

    //unsafe {
    //register_handler(13, Box::new(|e| gp_handler(e)));
    //register_handler(14, Box::new(|e| pf_handler(e)));
    //}
}

/// Establishes a route for a GSI on the IOAPIC.
///
/// # TODO
/// Currently this just enables everything and routes it to
/// core 0. This is because, we should probably just support MSI(X)
/// and don't invest a lot in legacy interrupts...
pub fn ioapic_establish_route(_gsi: u64, _core: u64) {
    use crate::arch::vspace::MapAction;
    use crate::memory::{paddr_to_kernel_vaddr, PAddr};

    for io_apic in topology::MACHINE_TOPOLOGY.io_apics() {
        debug!("Initialize IO APIC {:?}", io_apic);
        let addr = PAddr::from(io_apic.address as u64);

        // map it
        let kcb = crate::kcb::get_kcb();
        let mut plock = kcb.current_process();

        plock.as_mut().map(|p| {
            trace!(
                "Map IOAPIC at: {:#x}, p is at {:p}",
                PAddr::from(crate::arch::memory::KERNEL_BASE) + addr,
                p
            );

            // TODO: The mapping should be in global kernel-space!
            p.vspace
                .map_identity_with_offset(
                    PAddr::from(crate::arch::memory::KERNEL_BASE),
                    addr,
                    addr + x86::bits64::paging::BASE_PAGE_SIZE,
                    MapAction::ReadWriteKernel,
                )
                .expect("Can't map IO APIC?");
        });

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

pub fn enable() {
    unsafe {
        irq::enable();
    }
}

pub fn disable() {
    unsafe {
        irq::disable();
    }
}
