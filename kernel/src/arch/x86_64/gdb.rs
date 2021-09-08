#![allow(warnings)]

use crate::error::KError;

use gdbstub::target::ext::base::singlethread::SingleThreadOps;
use gdbstub::target::ext::base::singlethread::{GdbInterrupt, ResumeAction, StopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetResult};
use gdbstub::Connection;

use log::info;
use x86::io;

pub fn wait_for_gdb_connection(port: u16) -> Result<GdbSerial, KError> {
    let gdb = GdbSerial::new(port);

    info!("Waiting for a GDB connection (I/O port {:#x})...", port);
    info!("Use `target remote localhost:1234` in gdb to connect.");

    // Block until a GDB client connects:
    while !gdb.can_read() {
        core::hint::spin_loop();
    }

    info!("Debugger connected");
    Ok(gdb)
}

#[derive(Debug)]
pub struct GdbSerialErr;

/// Wrapper to communicate with GDB over the serial line.
#[derive(Debug, Eq, PartialEq)]
pub struct GdbSerial {
    port: u16,
    peeked: Option<u8>,
}

impl GdbSerial {
    /// Create a new GdbSerial connection.
    fn new(port: u16) -> Self {
        GdbSerial { port, peeked: None }
    }

    /// Determines if something is available to read.
    fn can_read(&self) -> bool {
        unsafe { (io::inb(self.port + 5) & 0b0000_0001) > 0 }
    }

    /// Read a byte from the serial line.
    fn read_byte(&self) -> u8 {
        assert!(self.can_read());
        unsafe { io::inb(self.port + 0) }
    }

    /// Is the serial port FIFO ready?
    fn can_write(&self) -> bool {
        unsafe { (io::inb(self.port + 5) & 0b0010_0000) > 0 }
    }

    /// Send the byte out the serial port
    fn write_byte(&self, byte: u8) {
        assert!(self.can_write());
        unsafe { io::outb(self.port, byte) }
    }
}

impl Connection for GdbSerial {
    type Error = GdbSerialErr;

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

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        while !self.can_write() {
            core::hint::spin_loop();
        }
        self.write_byte(byte);
        Ok(())
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        if !self.can_read() {
            Ok(None)
        } else {
            self.peeked = Some(self.read_byte());
            Ok(self.peeked)
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct GdbRemote;

impl GdbRemote {
    pub fn new() -> Self {
        Self
    }
}

impl Target for GdbRemote {
    type Error = ();
    type Arch = gdbstub_arch::x86::X86_64_SSE;

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }
}

impl SingleThreadOps for GdbRemote {
    fn resume(
        &mut self,
        action: ResumeAction,
        gdb_interrupt: GdbInterrupt<'_>,
    ) -> Result<StopReason<u64>, ()> {
        info!("resume {:?}", action);
        Ok(StopReason::Exited(0x0))
    }

    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::x86::reg::X86_64CoreRegs,
    ) -> TargetResult<(), Self> {
        info!("read_registers");

        // RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
        regs.regs[0] = 0x0;
        regs.regs[1] = 0x0;
        regs.regs[2] = 0x0;
        regs.regs[3] = 0x0;
        regs.regs[4] = 0x0;
        regs.regs[5] = 0x0;
        regs.regs[6] = 0x0;
        regs.regs[7] = 0x0;
        for i in 8..16 {
            regs.regs[i] = 0x0;
        }

        regs.rip = 0x0;
        regs.eflags = 0x0 as u32;

        // Segment registers: CS, SS, DS, ES, FS, GS
        regs.segments = gdbstub_arch::x86::reg::X86SegmentRegs {
            cs: 0x0,
            ss: 0x0,
            ds: 0x0,
            es: 0x0,
            fs: 0x0,
            gs: 0x0,
        };

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::x86::reg::X86_64CoreRegs,
    ) -> TargetResult<(), Self> {
        info!("write_registers {:?}", regs);
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, _data: &mut [u8]) -> TargetResult<(), Self> {
        info!("read_addrs start_addr {:#x}", start_addr);
        Ok(())
    }

    fn write_addrs(&mut self, start_addr: u64, _data: &[u8]) -> TargetResult<(), Self> {
        info!("write_addrs start_addr {:#x}", start_addr);
        Ok(())
    }
}
