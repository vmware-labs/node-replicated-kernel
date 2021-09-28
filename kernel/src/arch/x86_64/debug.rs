// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::sync::atomic::AtomicU16;
use core::sync::atomic::Ordering;

use klogger::sprintln;
use log::debug;
use x86::io;

use super::ExitReason;

static PORT1: u16 = 0x3f8; /* COM1 */
static PORT2: u16 = 0x2f8; /* COM2 */

/// Standard serial print port.
///
/// Might be changed through command line option, hence the atomic.
pub static SERIAL_PRINT_PORT: AtomicU16 = AtomicU16::new(PORT1);

/// QEMU debug exit device.
///
/// If you change this line, you must also adjust `run.py`.
static QEMU_DEBUG_EXIT_PORT: u16 = 0xf4;

/// GDB remote communication line.
///
/// If you change this line, you must also adjust `run.py`.
pub static GDB_REMOTE_PORT: u16 = PORT2;

pub fn init() {
    unsafe {
        for p in [PORT1, PORT2] {
            io::outb(p + 1, 0x00); // Disable all interrupts
            io::outb(p + 3, 0x80); // Enable DLAB (set baud rate divisor)
            io::outb(p + 0, 0x01); // Set divisor to 1 (lo byte) 115200 baud
            io::outb(p + 1, 0x00); //                  (hi byte)
            io::outb(p + 3, 0x03); // 8 bits, no parity, one stop bit
            io::outb(p + 2, 0xC7); // Enable FIFO, clear them, with 14-byte threshold
            io::outb(p + 1, 0x01); // Enable receive data IRQ
        }
    }

    debug!("serial initialized");
}

pub unsafe fn getc() -> char {
    let port = SERIAL_PRINT_PORT.load(Ordering::Relaxed);
    let scancode = io::inb(port + 0);
    scancode as char
}

/// Write a string to the output channel
pub unsafe fn puts(s: &str) {
    for b in s.bytes() {
        putb(b);
    }
}

/// Write a single byte to the output channel
pub unsafe fn putb(b: u8) {
    let port = SERIAL_PRINT_PORT.load(Ordering::Relaxed);

    // Wait for the serial SERIAL_PRINT_PORT's FIFO to be ready
    while (io::inb(port + 5) & 0b0010_0000) == 0 {}
    // Send the byte out the serial SERIAL_PRINT_PORT
    io::outb(port, b);
}

/// Shutdown the processor.
///
/// Currently we only support the debug exit method from qemu, which conveniently
/// allows us to supply an exit code for testing purposes.
pub fn shutdown(val: ExitReason) -> ! {
    unsafe {
        // For QEMU with debug-exit,iobase=0xf4,iosize=0x04
        // qemu will call: exit((val << 1) | 1);
        io::outb(QEMU_DEBUG_EXIT_PORT, val as u8);
    }

    // For CI run.py bare-metal execution, parses exit code
    // (Do not change this line without adjusting run.py)
    sprintln!("[shutdown-request] {}", val as u8);

    // TODO(bare-metal): Do some ACPI magic to shutdown things

    // In case this doesn't work we hang.
    loop {
        unsafe { x86::halt() };
    }
}

#[cfg(any(
    feature = "test-pfault-early",
    all(feature = "integration-test", feature = "test-pfault")
))]
#[inline(never)]
pub fn cause_pfault() {
    use super::memory::{paddr_to_kernel_vaddr, PAddr};

    unsafe {
        let paddr = PAddr::from(0xdeadbeefu64);
        let kernel_vaddr = paddr_to_kernel_vaddr(paddr);
        let ptr: *mut u64 = kernel_vaddr.as_mut_ptr();
        debug!("before causing the pfault");
        let val = *ptr;
        assert!(val != 0);
    }
}

#[cfg(any(
    feature = "test-gpfault-early",
    all(feature = "integration-test", feature = "test-gpfault")
))]
pub fn cause_gpfault() {
    // Note that int!(13) doesn't work in qemu. It doesn't push an error code properly for it.
    // So we cause a GP by loading garbage in the ss segment register.
    use x86::segmentation::{load_ss, SegmentSelector};
    unsafe {
        load_ss(SegmentSelector::new(99, x86::Ring::Ring3));
    }
}

#[cfg(feature = "test-double-fault")]
pub fn cause_double_fault() {
    unsafe {
        x86::int!(0x8);
    }
}

/// Verify that we're actually using the fault-stack
/// as part of the test
#[cfg(feature = "test-double-fault")]
pub fn assert_being_on_fault_stack() {
    let (low, high) = super::kcb::get_kcb().arch.fault_stack_range();
    let rsp = x86::current::registers::rsp();
    debug_assert!(
        rsp >= low && rsp <= high,
        "We're not using the `unrecoverable_fault_stack`."
    );
}
