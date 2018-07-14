use core::fmt;

use x86::bits64::segmentation::Descriptor64;
use x86::dtables;
use x86::io;
use x86::irq;
use x86::msr;
use x86::segmentation::{
    BuildDescriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
};
use x86::Ring;

const IDT_SIZE: usize = 256;
static mut IDT: [Descriptor64; IDT_SIZE] = [Descriptor64::NULL; IDT_SIZE];

static mut IRQ_HANDLERS: [unsafe fn(&ExceptionArguments); IDT_SIZE] = [unhandled_irq; IDT_SIZE];

unsafe fn unhandled_irq(a: &ExceptionArguments) {
    slog!("Got UNHANDLED IRQ: {:?}", a);
    loop {}
}

unsafe fn pf_handler(a: &ExceptionArguments) {
    slog!("Got page-fault: {:?}", a);
    loop {}
}

unsafe fn gp_handler(a: &ExceptionArguments) {
    let desc = &irq::EXCEPTIONS[a.vector as usize];
    slog!("Source: {}", desc.source);

    if a.exception > 0 {
        slog!(
            "Error value: {:?}",
            SegmentSelector::from_raw(a.exception as u16)
        );
    } else {
        slog!("No error!");
    }
    slog!("{:?}", a);
    loop {}
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
#[repr(C, packed)]
pub struct ExceptionArguments {
    vector: u64,
    exception: u64,
    eip: u64,
    cs: u64,
    eflags: u64,
}

impl fmt::Debug for ExceptionArguments {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            write!(
                f,
                "vec = 0x{:x} ex = 0x{:x} rip = 0x{:x}, cs = 0x{:x} eflags = 0x{:x}",
                self.vector, self.exception, self.eip, self.cs, self.eflags
            )
        }
    }
}

/// Rust entry point for exception handling (see isr.S).
/// TODO: does this need to be extern?
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_generic_exception(a: ExceptionArguments) {
    if a.vector < 16 {
        let desc = &irq::EXCEPTIONS[a.vector as usize];
        slog!("{}", desc);
    }
    slog!("{:?}", a);

    unsafe {
        assert!(a.vector < 256);
        acknowledge();
        IRQ_HANDLERS[a.vector as usize](&a);
    }
}

pub unsafe fn acknowledge() {
    // ACK the interrupt
    // TODO: Disable the PIC and get rid of this.
    io::outb(0x20, 0x20);
    // TODO: Need ACPI to disable PIC first before this does anything.
    msr::wrmsr(0x800 + 0xb, 0);
}

/// Work around for Intel quirk. Remap PIC vectors 0-16 to 32-48.
/// TODO: PIC handling should probably go into separate file.
pub unsafe fn pic_remap() {
    io::outb(0x20, 0x11);
    io::outb(0xA0, 0x11);
    io::outb(0x21, 0x20);
    io::outb(0xA1, 0x28);
    io::outb(0x21, 0x04);
    io::outb(0xA1, 0x02);
    io::outb(0x21, 0x01);
    io::outb(0xA1, 0x01);
    io::outb(0x21, 0x0);
    io::outb(0xA1, 0x0);

    // Keyboard interrupts only
    io::outb(0x21, 0b00000001);
    io::outb(0xa1, 0xff);
}

/// Registers a handler IRQ handler function.
pub unsafe fn register_handler(vector: usize, handler: unsafe fn(&ExceptionArguments)) {
    if vector > IDT_SIZE - 1 {
        slog!("Invalid vector!");
        return;
    }

    IRQ_HANDLERS[vector] = handler;
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
        slog!("Install IRQ handler");
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

        register_handler(13, gp_handler);
        register_handler(14, pf_handler);

        pic_remap();
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
