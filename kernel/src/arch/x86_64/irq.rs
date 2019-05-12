use core::fmt;

use alloc::boxed::Box;
use alloc::vec::Vec;
use x86::bits64::rflags;
use x86::bits64::segmentation::Descriptor64;
use x86::dtables;
use x86::io;
use x86::irq;
//use x86::msr;

use x86::segmentation::{
    BuildDescriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
};
use x86::Ring;

use crate::arch::debug;
use crate::panic::{backtrace, backtrace_from};
use crate::ExitReason;
use spin::Mutex;

use log::debug;

#[derive(Default)]
#[repr(packed)]
pub struct SaveArea {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

impl SaveArea {
    const fn empty() -> SaveArea {
        SaveArea {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
        }
    }
}

impl fmt::Debug for SaveArea {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            write!(
                f,
                "rax = {:>#18x} rbx = {:>#18x} rcx = {:>#18x} rdx = {:>#18x}
rsi = {:>#18x} rdi = {:>#18x} rbp = {:>#18x} rsp = {:>#18x}
r8  = {:>#18x} r9  = {:>#18x} r10 = {:>#18x} r11 = {:>#18x}
r12 = {:>#18x} r13 = {:>#18x} r14 = {:>#18x} r15 = {:>#18x}
rip = {:>#18x} rflags = {:?}",
                self.rax,
                self.rcx,
                self.rbx,
                self.rdx,
                self.rsi,
                self.rdi,
                self.rbp,
                self.rsp,
                self.r8,
                self.r9,
                self.r10,
                self.r11,
                self.r12,
                self.r13,
                self.r14,
                self.r15,
                self.rip,
                rflags::RFlags::from_raw(self.rflags)
            )
        }
    }
}

/// The isr.S code saves the registers in here in case an interrupt happens.
#[no_mangle]
pub static mut CURRENT_SAVE_AREA: SaveArea = SaveArea::empty();

const IDT_SIZE: usize = 256;
static mut IDT: [Descriptor64; IDT_SIZE] = [Descriptor64::NULL; IDT_SIZE];

lazy_static! {
    static ref IRQ_HANDLERS: Mutex<Vec<Box<Fn(&ExceptionArguments) -> () + Send + 'static>>> = {
        let mut vec: Vec<Box<Fn(&ExceptionArguments) -> () + Send + 'static>> =
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
    let csa = &CURRENT_SAVE_AREA;
    sprintln!("Register State:\n{:?}", csa);
    backtrace_from(csa.rbp, csa.rsp, csa.rip);

    debug::shutdown(ExitReason::UnhandledInterrupt);
}

unsafe fn pf_handler(a: &ExceptionArguments) {
    sprintln!("[IRQ] Page Fault");
    sprintln!(
        "{}",
        x86::irq::PageFaultError::from_bits_truncate(a.exception as u32)
    );

    // Print where the fault happend in the address-space:
    let faulting_address = x86::controlregs::cr2();
    sprint!("Faulting address: {:#x}", faulting_address);
    use crate::arch::kcb;
    kcb::try_get_kcb().map(|k| {
        sprintln!(
            " (in ELF: {:#x})",
            faulting_address - k.kernel_args().kernel_elf_offset.as_usize()
        )
    });

    // Print the RIP that triggered the fault:
    sprint!("Instruction Pointer: {:#x}", a.rip);
    kcb::try_get_kcb().map(|k| {
        sprintln!(
            " (in ELF: {:#x})",
            a.rip - k.kernel_args().kernel_elf_offset.as_u64()
        )
    });

    sprintln!("{:?}", a);
    let csa = &CURRENT_SAVE_AREA;
    sprintln!("Register State:\n{:?}", csa);

    backtrace_from(csa.rbp, csa.rsp, csa.rip);

    debug::shutdown(ExitReason::PageFault);
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
    use crate::arch::kcb;
    sprint!("Instruction Pointer: {:#x}", a.rip);
    kcb::try_get_kcb().map(|k| {
        sprintln!(
            " (in ELF: {:#x})",
            a.rip - k.kernel_args().kernel_elf_offset.as_u64()
        )
    });

    sprintln!("{:?}", a);
    let csa = &CURRENT_SAVE_AREA;
    sprintln!("Register State:\n{:?}", csa);
    backtrace_from(csa.rbp, csa.rsp, csa.rip);

    debug::shutdown(ExitReason::GeneralProtectionFault);
}

/// Import the ISR assembly handler and add it to our IDT (see isr.S).
macro_rules! idt_set {
    ($num:expr, $f:ident, $sel:expr, $flags:expr) => {{
        extern "C" {
            #[no_mangle]
            fn $f();
        }

        IDT[$num] = DescriptorBuilder::interrupt_descriptor($sel, $f as u64)
            .dpl(Ring::Ring0)
            .present()
            .finish();
    }};
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

/// Rust entry point for exception handling (see isr.S).
/// TODO: does this need to be extern?
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_generic_exception(a: ExceptionArguments) {
    unsafe {
        assert!(a.vector < 256);

        // Shortcut to handle protection and page faults
        // that lock and IRQ_HANDLERS thing requires a bit
        // too much machinery and is only set-up late in initialization
        // and unfortunately! sometimes things break early on...
        if a.vector == 0xd {
            gp_handler(&a);
            return;
        } else if a.vector == 0xe {
            pf_handler(&a);
            return;
        }

        trace!("handle_generic_exception {:?}", a);
        let vec_handlers = IRQ_HANDLERS.lock();
        (*vec_handlers)[a.vector as usize](&a);
    }
}

pub unsafe fn acknowledge() {
    crate::kcb::try_get_kcb().map(|k| {
        let mut apic = k.apic();
        apic.eoi();
    });
}

/// Registers a handler IRQ handler function.
pub unsafe fn register_handler(
    vector: usize,
    handler: Box<Fn(&ExceptionArguments) -> () + Send + 'static>,
) {
    if vector > IDT_SIZE - 1 {
        debug!("Invalid vector!");
        return;
    }

    info!("register irq handler for vector {}", vector);
    let mut handlers = IRQ_HANDLERS.lock();
    handlers[vector] = handler;
}

/// Initializes and loads the IDT into the CPU.
///
/// With this done we should be able to catch basic pfaults and gpfaults.
pub fn setup_idt() {
    unsafe {
        //let mut old_idt: dtables::DescriptorTablePointer<Descriptor64> = Default::default();
        //dtables::sidt(&mut old_idt);
        //trace!("IDT was: {:?}", old_idt);

        let idtptr = dtables::DescriptorTablePointer::new_from_slice(&IDT);
        dtables::lidt(&idtptr);
        trace!("IDT set to {:p}", &idtptr);

        // Note everything is declared as interrupt gates for now.
        // Trap and Interrupt gates are similar,
        // and their descriptors are structurally the same,
        // they differ only in the "type" field.
        // The difference is that for interrupt gates,
        // interrupts are automatically disabled upon entry
        // and re-enabled upon IRET which restores the saved EFLAGS.

        debug!("Install IRQ handler");
        let seg = SegmentSelector::new(1, Ring::Ring0);
        idt_set!(0, isr_handler0, seg, 0x8E);
        idt_set!(1, isr_handler1, seg, 0x8E);
        idt_set!(2, isr_handler2, seg, 0x8E);
        idt_set!(3, isr_handler3, seg, 0x8E);
        idt_set!(4, isr_handler4, seg, 0x8E);
        idt_set!(5, isr_handler5, seg, 0x8E);
        idt_set!(6, isr_handler6, seg, 0x8E);
        idt_set!(7, isr_handler7, seg, 0x8E);
        idt_set!(8, isr_handler8, seg, 0x8E);
        idt_set!(9, isr_handler9, seg, 0x8E);
        idt_set!(10, isr_handler10, seg, 0x8E);
        idt_set!(11, isr_handler11, seg, 0x8E);
        idt_set!(12, isr_handler12, seg, 0x8E);
        idt_set!(13, isr_handler13, seg, 0x8E);
        idt_set!(14, isr_handler14, seg, 0x8E);
        idt_set!(15, isr_handler15, seg, 0x8E);

        idt_set!(32, isr_handler32, seg, 0x8E);
        idt_set!(33, isr_handler33, seg, 0x8E);
        idt_set!(34, isr_handler34, seg, 0x8E);
        idt_set!(35, isr_handler35, seg, 0x8E);
        idt_set!(36, isr_handler36, seg, 0x8E);
        idt_set!(37, isr_handler37, seg, 0x8E);
        idt_set!(38, isr_handler38, seg, 0x8E);
        idt_set!(39, isr_handler39, seg, 0x8E);
        idt_set!(40, isr_handler40, seg, 0x8E);
        idt_set!(41, isr_handler41, seg, 0x8E);
        idt_set!(42, isr_handler42, seg, 0x8E);
        idt_set!(43, isr_handler43, seg, 0x8E);
        idt_set!(44, isr_handler44, seg, 0x8E);
        idt_set!(45, isr_handler45, seg, 0x8E);
        idt_set!(46, isr_handler46, seg, 0x8E);
        idt_set!(47, isr_handler47, seg, 0x8E);
    }
    info!("IDT table initialized.");
}

/// Finishes the initialization of IRQ handlers once we have memory allocation.
pub fn init_irq_handlers() {
    lazy_static::initialize(&IRQ_HANDLERS);

    unsafe {
        //register_handler(13, Box::new(|e| gp_handler(e)));
        //register_handler(14, Box::new(|e| pf_handler(e)));
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
