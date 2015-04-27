use prelude::*;
use x86::io;
use super::irq;

use super::process::{current_process};

static PORT0: u16 = 0x3f8;   /* COM1 */
static COM1_IRQ: usize = 4+32;

pub fn init() {
    unsafe {
        io::outb(PORT0 + 1, 0x00);    // Disable all interrupts
        io::outb(PORT0 + 3, 0x80);    // Enable DLAB (set baud rate divisor)
        io::outb(PORT0 + 0, 0x01);    // Set divisor to 1 (lo byte) 115200 baud
        io::outb(PORT0 + 1, 0x00);    //                  (hi byte)
        io::outb(PORT0 + 3, 0x03);    // 8 bits, no parity, one stop bit
        io::outb(PORT0 + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
        io::outb(PORT0 + 1, 0x01);    // Enable receive data IRQ
        //io::outb(PORT0 + 1, 0x00);    // Disable receive data IRQ
    }
    log!("serial initialized");
    unsafe { irq::register_handler(COM1_IRQ, receive_serial_irq); }

}

unsafe fn receive_serial_irq(a: &irq::ExceptionArguments) {
    while io::inb(PORT0 + 5) & 0x1 > 0 {
        let scancode = io::inb(PORT0 + 0);
        //let mut cp = current_process.lock();
        //log!("{:?}", *cp);
        putb(scancode);
    }
    //loop {}
}

/// Write a string to the output channel
pub unsafe fn puts(s: &str)
{
	for b in s.bytes()
	{
		putb(b);
	}
}

/// Write a single byte to the output channel
pub unsafe fn putb(b: u8)
{
	// Wait for the serial PORT0's FIFO to be ready
	while (io::inb(PORT0+5) & 0x20) == 0
	{}

	// Send the byte out the serial PORT0
	io::outb(PORT0, b);
}
