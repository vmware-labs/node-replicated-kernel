// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! GDB serial line connection implementation.

use bit_field::BitField;
use gdbstub::{Connection, ConnectionExt};
use x86::io;

use crate::error::KError;

#[derive(Debug)]
pub(crate) struct GdbSerialErr;

/// Wrapper to communicate with GDB over the serial line.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct GdbSerial {
    port: u16,
    peeked: Option<u8>,
}

impl GdbSerial {
    const INTERRUPT_ENABLE_REGISTER: u16 = 1;
    const _IRQ_IDENTIFICATION_REGISTER: u16 = 2;
    const LINE_STATUS_REGISTER: u16 = 5;

    /// Create a new GdbSerial connection.
    pub(crate) fn new(port: u16) -> Self {
        GdbSerial { port, peeked: None }
    }

    /// Determines if something is available to read.
    pub(crate) fn can_read(&self) -> bool {
        const DATA_READY_BIT: usize = 0;
        let line_status = unsafe { io::inb(self.port + GdbSerial::LINE_STATUS_REGISTER) };
        line_status.get_bit(DATA_READY_BIT)
    }

    /// Read a byte from the serial line.
    fn read_byte(&self) -> u8 {
        assert!(self.can_read());
        unsafe { io::inb(self.port + 0) }
    }

    /// Is the serial port FIFO ready?
    fn can_write(&self) -> bool {
        const TRANSMIT_EMPTY_BIT: usize = 5;
        let line_status = unsafe { io::inb(self.port + GdbSerial::LINE_STATUS_REGISTER) };
        line_status.get_bit(TRANSMIT_EMPTY_BIT)
    }

    /// Send the byte out the serial port
    fn write_byte(&self, byte: u8) {
        assert!(self.can_write());
        unsafe { io::outb(self.port, byte) }
    }

    pub(crate) fn _iir(&self) -> u8 {
        unsafe { io::inb(self.port + GdbSerial::_IRQ_IDENTIFICATION_REGISTER) }
    }

    /// Enable receive interrupt.
    pub(crate) fn enable_irq(&self) {
        unsafe {
            io::outb(self.port + GdbSerial::INTERRUPT_ENABLE_REGISTER, 1);
        }
    }

    /// Disable all interrupts.
    pub(crate) fn disable_irq(&self) {
        unsafe {
            io::outb(self.port + GdbSerial::INTERRUPT_ENABLE_REGISTER, 0x00);
        }
    }
}

impl Connection for GdbSerial {
    type Error = KError;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        while !self.can_write() {
            core::hint::spin_loop();
        }
        self.write_byte(byte);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ConnectionExt for GdbSerial {
    fn read(&mut self) -> Result<u8, Self::Error> {
        if let Some(byte) = self.peeked {
            self.peeked = None;
            Ok(byte)
        } else {
            while !self.can_read() {
                core::hint::spin_loop();
            }
            let b = self.read_byte();
            Ok(b)
        }
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        if !self.can_read() {
            Ok(None)
        } else {
            let b = self.read_byte();
            self.peeked = Some(b);
            Ok(self.peeked)
        }
    }
}
