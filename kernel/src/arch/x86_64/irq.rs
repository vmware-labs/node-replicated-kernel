use core::fmt;

use alloc::boxed::Box;
use alloc::vec::Vec;
use x86::bits64::rflags;
use x86::bits64::segmentation::Descriptor64;
use x86::dtables;
use x86::io;
use x86::irq;
use x86::msr;

use alloc::vec;

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

#[no_mangle]
pub static CURRENT_SAVE_AREA: SaveArea = SaveArea::empty();

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
    sprintln!("Faulting address: {:#x}", x86::controlregs::cr2());

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

        if a.vector == 0xd {
            gp_handler(&a);
        } else if a.vector == 0xc {
            pf_handler(&a);
        }

        trace!("handle_generic_exception {:?}", a);
        let vec_handlers = IRQ_HANDLERS.lock();
        (*vec_handlers)[a.vector as usize](&a);
    }
}

const PIC1_CMD: u16 = 0x20;
const PIC2_CMD: u16 = 0xA0;

pub unsafe fn acknowledge() {
    // ACK the interrupt
    // TODO: Disable the PIC and get rid of this.
    io::outb(PIC2_CMD, 0x20);
    io::outb(PIC1_CMD, 0x20);

    // TODO: Need ACPI to disable PIC first before this does anything.
    //msr::wrmsr(0x800 + 0xb, 0);
}

/// Work around for Intel quirk. Remap PIC vectors 0-16 to 32-48.
/// TODO: PIC handling should probably go into separate file.
pub unsafe fn pic_remap() {
    const PIC1_DATA: u16 = 0x21;
    const PIC2_DATA: u16 = 0xA1;

    let m1 = io::inb(PIC1_DATA);
    let m2 = io::inb(PIC2_DATA);

    pub const ICW4: u8 = 0x01;
    pub const INIT: u8 = 0x10;
    pub const ICW4_8086: u8 = 0x1;

    io::outb(PIC1_CMD, ICW4 | INIT);
    io::outb(PIC2_CMD, ICW4 | INIT);

    io::outb(PIC1_DATA, 32);
    io::outb(PIC2_DATA, 32 + 8);

    io::outb(PIC1_DATA, 0b0000_0100);
    io::outb(PIC2_DATA, 2);

    io::outb(PIC1_DATA, ICW4_8086);
    io::outb(PIC2_DATA, ICW4_8086);

    trace!("PIC1 mask is {:#b}", m1);
    trace!("PIC2 mask is {:#b}", m2);

    // Established Mapping
    // 0 -> 32
    // 1 -> 33
    // 2 -> 34
    // 3 -> 35
    // 4 -> 36
    // 5 -> 37: Serial?
    // 6 -> 38
    // 7 -> 39

    // 8 -> 40
    // 9 -> 41
    // 10 -> 42
    // 11 -> 43: e1000 NIC
    // 12 -> 44
    // 13 -> 45
    // 14 -> 46
    // 15 -> 47

    const KEYBOARD_IRQ: u8 = 1 << 4; // IRQ 5 -> 37
    const E1000_IRQ: u8 = 1 << 3; // IRQ 11 -> 43 (11-8 = 3)
    assert_eq!((KEYBOARD_IRQ | 0b1), 0b10001);
    assert_eq!(!(E1000_IRQ), 0b11110111);

    io::outb(PIC1_DATA, !(1 << 2));
    io::outb(PIC2_DATA, 0b1111_0111);
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
pub fn setup_idt() {
    unsafe {
        let idtptr = dtables::DescriptorTablePointer::new_from_slice(&IDT);
        dtables::lidt(&idtptr);

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

        register_handler(13, Box::new(|e| gp_handler(e)));
        register_handler(14, Box::new(|e| pf_handler(e)));

        pic_remap();
        info!("Completed pic remap");
        lazy_static::initialize(&IRQ_HANDLERS);
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
