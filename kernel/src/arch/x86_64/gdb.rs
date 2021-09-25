#![allow(warnings)]
use core::convert::TryInto;
use core::lazy;
use core::num::NonZeroUsize;

use gdbstub::target::ext::base::multithread::ThreadStopReason;
use gdbstub::target::ext::base::singlethread::{
    GdbInterrupt, ResumeAction, SingleThreadOps, StopReason,
};
use gdbstub::target::ext::base::{BaseOps, SingleRegisterAccess, SingleRegisterAccessOps};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps,
    SwBreakpointOps, WatchKind,
};
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets, SectionOffsetsOps};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub::{
    Connection, ConnectionExt, DisconnectReason, GdbStub, GdbStubError, GdbStubStateMachine,
};
use gdbstub_arch::x86::reg::id::{X86SegmentRegId, X86_64CoreRegId};
use gdbstub_arch::x86::X86_64_SSE;

use lazy_static::lazy_static;
use log::{error, info, trace};
use spin::Mutex;
use x86::bits64::rflags::RFlags;
use x86::debugregs;
use x86::io;

use super::debug::GDB_REMOTE_PORT;
use crate::error::KError;
use crate::memory::vspace::AddressSpace;
use crate::memory::{VAddr, BASE_PAGE_SIZE};

/// Indicates the reason for interruption (e.g. a breakpoint was hit).
pub enum KCoreStopReason {
    /// DebugInterrupt was received.
    ///
    /// This normally means we hit a hardware breakpoint, watchpoint, rflags
    /// step-mode was enabled or we are at the start of the kernel program)
    DebugInterrupt,
    /// A breakpoint was hit.
    ///
    /// This usually means gdb fiddled with the instructions and inserted an
    /// `int 3` somewhere it deemed necessary.
    BreakpointInterrupt,
}

lazy_static! {
    /// The GDB connection state machine.
    ///
    /// This is a state machine that handles the communication with the GDB.
    pub static ref GDB_STUB: Mutex<Option<gdbstub::GdbStubStateMachine<'static, KernelDebugger, GdbSerial>>> = {
        let connection = wait_for_gdb_connection(GDB_REMOTE_PORT).expect("Can't connect to GDB");
        Mutex::new(Some(gdbstub::GdbStub::new(connection).run_state_machine().expect("Can't start GDB session")))
    };
}

/// Wait until a GDB connection is established (e.g., until we can read
/// something from the serial line).
fn wait_for_gdb_connection(port: u16) -> Result<GdbSerial, KError> {
    let gdb = GdbSerial::new(port);

    info!("Waiting for a GDB connection (I/O port {:#x})...", port);
    // If you modify the next line, you also need to adjust the corresponding
    // line in the `s02_gdb` integration test:
    info!("Use `target remote localhost:1234` in gdb to connect.");

    // Block until a GDB client connects:
    while !gdb.can_read() {
        core::hint::spin_loop();
    }

    // If you modify the next line, you also need to adjust the corresponding
    // line in the `s02_gdb` integration test:
    info!("Debugger connected.");
    Ok(gdb)
}

/// Resume the gdb client connection by passing an optional event for the
/// interruption.
///
/// # Arguments
/// - `resume_with`: Should probably always be Some(reason) except the first
///   time after connecting.
pub fn event_loop(reason: KCoreStopReason) -> Result<(), KError> {
    let mut gdb_stm = GDB_STUB.lock().take().unwrap();
    let target = super::kcb::get_kcb()
        .arch
        .kdebug
        .as_mut()
        .expect("Need a target");

    let mut resume_with = target.determine_stop_reason(reason);

    loop {
        gdb_stm = match gdb_stm {
            GdbStubStateMachine::Pump(mut gdb_stm_inner) => {
                // This means we expect stuff on the serial line (from GDB)
                // Let's read and react to it:
                let byte = gdb_stm_inner.borrow_conn().read()?;
                match gdb_stm_inner.pump(target, byte) {
                    Ok((_, Some(disconnect_reason))) => {
                        match disconnect_reason {
                            DisconnectReason::Disconnect => info!("GDB Disconnected"),
                            DisconnectReason::TargetExited(_) => info!("Target exited"),
                            DisconnectReason::TargetTerminated(_) => info!("Target halted"),
                            DisconnectReason::Kill => info!("GDB sent a kill command"),
                        }
                        break;
                    }
                    Ok((gdb_stm_new, None)) => gdb_stm_new,
                    Err(GdbStubError::TargetError(_e)) => {
                        info!("Target raised a fatal error");
                        break;
                    }
                    Err(e) => {
                        error!("gdbstub internal error {:?}", e);
                        break;
                    }
                }
            }
            GdbStubStateMachine::DeferredStopReason(mut gdb_stm_inner) => {
                // need to "select" on both the data coming over the connection
                // (which gets passed to `pump`) and whatever mechanism it is
                // using to detect stop events.
                //let byte = gdb
                //    .borrow_conn()
                //    .read()
                //    .map_err(gdbstub::GdbStubError::ConnectionRead)?;

                // This means we need to continue executing stuff, so let's put
                // our STM back in `GDB_STUB` and exit.
                if let Some(reason) = resume_with.take() {
                    match gdb_stm_inner.deferred_stop_reason(target, reason) {
                        Ok((_, Some(disconnect_reason))) => {
                            match disconnect_reason {
                                DisconnectReason::Disconnect => info!("GDB Disconnected"),
                                DisconnectReason::TargetExited(_) => info!("Target exited"),
                                DisconnectReason::TargetTerminated(_) => info!("Target halted"),
                                DisconnectReason::Kill => info!("GDB sent a kill command"),
                            }
                            break;
                        }
                        Ok((gdb_stm_new, None)) => gdb_stm_new,
                        Err(GdbStubError::TargetError(_e)) => {
                            info!("Target raised a fatal error");
                            break;
                        }
                        Err(e) => {
                            error!("gdbstub internal error {:?}", e);
                            break;
                        }
                    }
                } else {
                    // probably need to pump here?
                    let r = GDB_STUB
                        .lock()
                        .replace(GdbStubStateMachine::DeferredStopReason(gdb_stm_inner));
                    assert!(
                        r.is_none(),
                        "Put something in GDB_STUB which we shouldn't have..."
                    );
                    break;
                }
            }
        }
    }

    match target.resume_with {
        Some(ResumeAction::Continue) => {
            trace!("Resume execution.");
            let kcb = super::kcb::get_kcb();
            // If we were stepping, we need to remove the TF bit again for resuming
            if let Some(saved) = &mut kcb.arch.save_area {
                let mut rflags = RFlags::from_bits_truncate(saved.rflags);
                rflags.remove(x86::bits64::rflags::RFlags::FLAGS_TF);
                saved.rflags = rflags.bits();
            }
        }
        Some(ResumeAction::Step) => {
            trace!("Step execution, set TF flag.");
            let kcb = super::kcb::get_kcb();
            if let Some(saved) = &mut kcb.arch.save_area {
                saved.rflags |= RFlags::FLAGS_TF.bits();
            }
        }
        _ => {
            unimplemented!("Resume strategy not handled...");
        }
    }

    Ok(())
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
    type Error = KError;

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
            Ok(Some(self.read_byte()))
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ConnectionExt for GdbSerial {
    fn read(&mut self) -> Result<u8, Self::Error> {
        //        if let Some(byte) = self.peeked {
        //            self.peeked = None;
        //            Ok(byte)
        //        } else {
        while !self.can_read() {
            core::hint::spin_loop();
        }
        let b = self.read_byte();
        Ok(b)
        //        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum BreakType {
    /// For instructions
    Breakpoint,
    /// For data access/writes
    Watchpoint(WatchKind),
}

/// A kernel level debug implementation that can interface with GDB over remote
/// serial protocol.
pub struct KernelDebugger {
    hw_break_points: [Option<(VAddr, BreakType)>; 4],
    resume_with: Option<ResumeAction>,
}

impl KernelDebugger {
    const GLOBAL_BP_FLAG: bool = true;

    pub fn new() -> Self {
        Self {
            hw_break_points: [None; 4],
            resume_with: None,
        }
    }

    /// Figures out why a core got a debug interrupt by looking through the
    /// hardware debug register and reading which one was hit.
    ///
    // Also does some additional stuff like re-enabling the breakpoints.
    fn determine_stop_reason(&mut self, reason: KCoreStopReason) -> Option<ThreadStopReason<u64>> {
        match reason {
            KCoreStopReason::BreakpointInterrupt => {
                Some(ThreadStopReason::HwBreak(NonZeroUsize::new(1).unwrap()))
            }
            KCoreStopReason::DebugInterrupt => {
                // Safety: We are in the kernel so we can access dr6.
                let mut dr6 = unsafe { debugregs::dr6() };

                let bp = if dr6.contains(debugregs::Dr6::B0) {
                    dr6.remove(debugregs::Dr6::B0);
                    self.hw_break_points[0]
                } else if dr6.contains(debugregs::Dr6::B1) {
                    dr6.remove(debugregs::Dr6::B1);
                    self.hw_break_points[1]
                } else if dr6.contains(debugregs::Dr6::B2) {
                    dr6.remove(debugregs::Dr6::B2);
                    self.hw_break_points[2]
                } else if dr6.contains(debugregs::Dr6::B3) {
                    dr6.remove(debugregs::Dr6::B3);
                    self.hw_break_points[3]
                } else {
                    // If None, we are either single-stepping (debugregs::Dr6::BS,
                    // handled below) or are at the start of the kernel (no
                    // breakpoints were set yet)
                    None
                };

                // Map things to a gdbstub stop reason:
                let stop: Option<ThreadStopReason<u64>> =
                    if let Some((va, BreakType::Breakpoint)) = bp {
                        info!("stop reason is hwbreak at {:?}", va);
                        Some(ThreadStopReason::HwBreak(NonZeroUsize::new(1).unwrap()))
                    } else if let Some((va, BreakType::Watchpoint(kind))) = bp {
                        Some(ThreadStopReason::Watch {
                            tid: NonZeroUsize::new(1).unwrap(),
                            kind,
                            addr: va.as_u64(),
                        })
                    } else if dr6.contains(debugregs::Dr6::BS) {
                        // When the BS flag is set, any of the other debug status bits also may be set.
                        assert_eq!(
                            self.resume_with,
                            Some(ResumeAction::Step),
                            "Single-stepping only happens in resume."
                        );
                        dr6.remove(debugregs::Dr6::BS);
                        info!("stop reason is DoneStep");
                        Some(ThreadStopReason::DoneStep)
                    } else {
                        None
                    };

                // Sanity check that we indeed handled all bits in dr6 (except RTM
                // which isn't a condition):
                if !dr6.difference(debugregs::Dr6::RTM).is_empty() {
                    // The code assumes that only one BP (or BS) condition gets set
                    // for a single IRQ. If multiple conditions can trigger per IRQ,
                    // we need to rethink this code.
                    //
                    // Maybe we have to handle every potential flag in dr6 in some
                    // loop one after the other, or ignore some? For now, we just
                    // log and then clear/ignore the unhandled bits:
                    error!("Unhandled/ignored these conditions in dr6: {:?}", dr6);
                    dr6 = debugregs::Dr6::empty(); // This will clear RTM (we don't use this atm.)
                }

                unsafe { debugregs::dr6_write(dr6) };

                stop
            }
        }
    }
}

impl Target for KernelDebugger {
    type Error = KError;
    type Arch = X86_64_SSE;

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn section_offsets(&mut self) -> Option<SectionOffsetsOps<Self>> {
        Some(self)
    }

    fn breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }
}

impl Breakpoints for KernelDebugger {
    fn sw_breakpoint(&mut self) -> Option<SwBreakpointOps<Self>> {
        None
    }

    fn hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }

    fn hw_watchpoint(&mut self) -> Option<HwWatchpointOps<Self>> {
        Some(self)
    }
}

impl SingleThreadOps for KernelDebugger {
    fn resume(
        &mut self,
        action: ResumeAction,
        gdb_interrupt: GdbInterrupt<'_>,
    ) -> Result<Option<StopReason<u64>>, KError> {
        self.resume_with = Some(action);
        trace!("resume_with =  {:?}", action);

        // If the target is running under the more advanced GdbStubStateMachine
        // API, it is possible to "defer" reporting a stop reason to some point
        // outside of the resume implementation by returning None.
        Ok(None)
    }

    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::x86::reg::X86_64CoreRegs,
    ) -> TargetResult<(), Self> {
        trace!("read_registers");
        let kcb = super::kcb::get_kcb();
        if let Some(saved) = &kcb.arch.save_area {
            // RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
            regs.regs[00] = saved.rax;
            regs.regs[01] = saved.rbx;
            regs.regs[02] = saved.rcx;
            regs.regs[03] = saved.rdx;
            regs.regs[04] = saved.rsi;
            regs.regs[05] = saved.rdi;
            regs.regs[06] = saved.rbp;
            regs.regs[07] = saved.rsp;
            regs.regs[08] = saved.r8;
            regs.regs[09] = saved.r9;
            regs.regs[10] = saved.r10;
            regs.regs[11] = saved.r11;
            regs.regs[12] = saved.r12;
            regs.regs[13] = saved.r13;
            regs.regs[14] = saved.r14;
            regs.regs[15] = saved.r15;

            regs.rip = saved.rip;
            regs.eflags = saved.rflags.try_into().unwrap();

            // Segment registers: CS, SS, DS, ES, FS, GS
            regs.segments = gdbstub_arch::x86::reg::X86SegmentRegs {
                cs: saved.cs.try_into().unwrap(),
                ss: saved.ss.try_into().unwrap(),
                ds: 0x0, // Don't bother with ds; should be irrelevant on 64bit
                es: 0x0, // Don't bother with es; should be irrelevant on 64bit
                fs: saved.fs.try_into().unwrap(),
                gs: saved.gs.try_into().unwrap(),
            };

            // TODO(unimplemented): Add SIMD registers here
        }
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::x86::reg::X86_64CoreRegs,
    ) -> TargetResult<(), Self> {
        trace!("write_registers {:?}", regs);
        let kcb = super::kcb::get_kcb();
        if let Some(saved) = &mut kcb.arch.save_area {
            // RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
            saved.rax = regs.regs[00];
            saved.rbx = regs.regs[01];
            saved.rcx = regs.regs[02];
            saved.rdx = regs.regs[03];
            saved.rsi = regs.regs[04];
            saved.rdi = regs.regs[05];
            saved.rbp = regs.regs[06];
            saved.rsp = regs.regs[07];
            saved.r8 = regs.regs[08];
            saved.r9 = regs.regs[09];
            saved.r10 = regs.regs[10];
            saved.r11 = regs.regs[11];
            saved.r12 = regs.regs[12];
            saved.r13 = regs.regs[13];
            saved.r14 = regs.regs[14];
            saved.r15 = regs.regs[15];

            saved.rip = regs.rip;
            saved.rflags = regs.eflags.try_into().unwrap();

            // Segment registers: CS, SS, DS, ES, FS, GS
            saved.cs = regs.segments.cs.try_into().unwrap();
            saved.ss = regs.segments.ss.try_into().unwrap();
            // ignore ss, ds because we don't use it.
            // saved.ds = regs.segments.ds.try_into().unwrap();
            // saved.es = regs.segments.es.try_into().unwrap();
            saved.fs = regs.segments.fs.try_into().unwrap();
            saved.gs = regs.segments.gs.try_into().unwrap();

            // TODO(unimplemented): Add SIMD registers here
        }
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<(), Self> {
        info!("read_addr {:#x}", start_addr);
        // (Un)Safety: Well, this can easily violate the rust aliasing model
        // because when we arrive in the debugger; there might some mutable
        // reference to the PTs somewhere in a context that was modifying the
        // PTs. We'll just have to accept this for debugging.
        let pt = unsafe { super::vspace::page_table::ReadOnlyPageTable::current() };

        let start_addr: usize = start_addr.try_into().unwrap();
        for i in 0..data.len() {
            let va = VAddr::from(start_addr + i);

            // Check access rights for start of every new page we encounter (and
            // for the first byte that might start within a page)
            if i == 0 || (start_addr + i) % BASE_PAGE_SIZE == 0 {
                match pt.resolve(va) {
                    Ok((pa, rights)) => {
                        if !rights.is_readable() {
                            // Mapped but not read-able (this can't really happen would mean
                            // something like swapped out but we don't do that)
                            return Err(TargetError::NonFatal);
                        }
                    }
                    Err(_) => {
                        error!("Target page was not mapped.");
                        // Target page was not mapped
                        return Err(TargetError::NonFatal);
                    }
                }
            }

            // Read the byte
            let ptr: *const u8 = va.as_ptr();
            // Safety: This should be ok, see all the effort above...
            data[i] = unsafe { *ptr };
        }

        Ok(())
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
        info!("write_addrs {:#x}", start_addr);

        // (Un)Safety: Well, this can easily violate the rust aliasing model
        // because when we arrive in the debugger; there might some mutable
        // reference to the PTs somewhere in a context that was modifying the
        // PTs. We'll just have to accept this for debugging.
        let pt = unsafe { super::vspace::page_table::ReadOnlyPageTable::current() };

        let start_addr: usize = start_addr.try_into().unwrap();
        for (i, payload) in data.iter().enumerate() {
            let va = VAddr::from(start_addr + i);

            // Check access rights for start of every new page that we encounter
            // (and for the first byte that might start within a page)
            if i == 0 || (start_addr + i) % BASE_PAGE_SIZE == 0 {
                match pt.resolve(va) {
                    Ok((pa, rights)) => {
                        if !rights.is_writable() {
                            if rights.is_executable() {
                                error!("Target page as read-execute. Can't write at address.");
                                error!("If you were trying to set a breakpoint use `hbreak` instead of `break`");
                            } else {
                                error!("Target page mapped as read-only. Can't write at address.");
                            }
                            return Err(TargetError::NonFatal);
                        }
                    }
                    Err(_) => {
                        // Target page was not mapped
                        error!("Target page not mapped.");
                        return Err(TargetError::NonFatal);
                    }
                }
            }

            // (Un)Safety: gdb writing in random memory locations? Surely this
            // won't end safely.
            let ptr: *mut u8 = va.as_mut_ptr();
            unsafe { *ptr = *payload };
        }

        Ok(())
    }

    fn single_register_access(&mut self) -> Option<SingleRegisterAccessOps<(), Self>> {
        Some(self)
        //None
    }
}

impl SingleRegisterAccess<()> for KernelDebugger {
    fn read_register(
        &mut self,
        tid: (),
        reg_id: X86_64CoreRegId,
        dst: &mut [u8],
    ) -> TargetResult<(), Self> {
        info!("read_register {:?}", reg_id);
        let kcb = super::kcb::get_kcb();

        if let Some(saved) = &mut kcb.arch.save_area {
            match reg_id {
                X86_64CoreRegId::Gpr(00) => dst.copy_from_slice(&saved.rax.to_le_bytes()),
                X86_64CoreRegId::Gpr(01) => dst.copy_from_slice(&saved.rbx.to_le_bytes()),
                X86_64CoreRegId::Gpr(02) => dst.copy_from_slice(&saved.rcx.to_le_bytes()),
                X86_64CoreRegId::Gpr(03) => dst.copy_from_slice(&saved.rdx.to_le_bytes()),
                X86_64CoreRegId::Gpr(04) => dst.copy_from_slice(&saved.rsi.to_le_bytes()),
                X86_64CoreRegId::Gpr(05) => dst.copy_from_slice(&saved.rdi.to_le_bytes()),
                X86_64CoreRegId::Gpr(06) => dst.copy_from_slice(&saved.rbp.to_le_bytes()),
                X86_64CoreRegId::Gpr(07) => dst.copy_from_slice(&saved.rsp.to_le_bytes()),
                X86_64CoreRegId::Gpr(08) => dst.copy_from_slice(&saved.r8.to_le_bytes()),
                X86_64CoreRegId::Gpr(09) => dst.copy_from_slice(&saved.r9.to_le_bytes()),
                X86_64CoreRegId::Gpr(10) => dst.copy_from_slice(&saved.r10.to_le_bytes()),
                X86_64CoreRegId::Gpr(11) => dst.copy_from_slice(&saved.r11.to_le_bytes()),
                X86_64CoreRegId::Gpr(12) => dst.copy_from_slice(&saved.r12.to_le_bytes()),
                X86_64CoreRegId::Gpr(13) => dst.copy_from_slice(&saved.r13.to_le_bytes()),
                X86_64CoreRegId::Gpr(14) => dst.copy_from_slice(&saved.r14.to_le_bytes()),
                X86_64CoreRegId::Gpr(15) => dst.copy_from_slice(&saved.r15.to_le_bytes()),
                X86_64CoreRegId::Rip => {
                    assert!(dst.len() == 8);
                    dst.copy_from_slice(&saved.rip.to_le_bytes())
                }
                X86_64CoreRegId::Eflags => {
                    let rflags: u32 = saved.rflags.try_into().unwrap();
                    dst.copy_from_slice(&rflags.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::CS) => {
                    let cs: u32 = saved.cs.try_into().unwrap();
                    dst.copy_from_slice(&cs.to_le_bytes())
                }

                X86_64CoreRegId::Segment(X86SegmentRegId::SS) => {
                    let ss: u32 = saved.ss.try_into().unwrap();
                    dst.copy_from_slice(&ss.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::DS) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::ES) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::FS) => {
                    let fs: u32 = saved.fs.try_into().unwrap();
                    dst.copy_from_slice(&fs.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::GS) => {
                    let gs: u32 = saved.gs.try_into().unwrap();
                    dst.copy_from_slice(&gs.to_le_bytes())
                }
                //X86_64CoreRegId::St(u8) => {},
                //X86_64CoreRegId::Fpu(X87FpuInternalRegId) => {},
                //X86_64CoreRegId::Xmm(u8) => {},
                //X86_64CoreRegId::Mxcsr => {},
                missing => {
                    error!("Unimplemented register {:?}", missing);
                    return Err(TargetError::NonFatal);
                }
            };

            Ok(())
        } else {
            Err(TargetError::NonFatal)
        }
    }

    fn write_register(
        &mut self,
        tid: (),
        reg_id: X86_64CoreRegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        error!("write_register {:?} {:?}", reg_id, val);
        let kcb = super::kcb::get_kcb();

        if let Some(saved) = &mut kcb.arch.save_area {
            match reg_id {
                X86_64CoreRegId::Gpr(00) => {
                    saved.rax =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(01) => {
                    saved.rbx =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(02) => {
                    saved.rcx =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(03) => {
                    saved.rdx =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(04) => {
                    saved.rsi =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(05) => {
                    saved.rdi =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(06) => {
                    saved.rbp =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(07) => {
                    saved.rsp =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(08) => {
                    saved.r8 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(09) => {
                    saved.r9 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(10) => {
                    saved.r10 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(11) => {
                    saved.r11 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(12) => {
                    saved.r12 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(13) => {
                    saved.r13 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(14) => {
                    saved.r14 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(15) => {
                    saved.r15 =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Rip => {
                    assert!(val.len() == 8);
                    info!("before rip {:#x}", saved.rip);
                    saved.rip =
                        u64::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?);
                    info!("set rip {:#x}", saved.rip);
                    return Ok(());
                }
                X86_64CoreRegId::Eflags => {
                    saved.rflags =
                        u32::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?)
                            as u64;
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::CS) => {
                    saved.cs =
                        u32::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?)
                            as u64;
                }

                X86_64CoreRegId::Segment(X86SegmentRegId::SS) => {
                    saved.ss =
                        u32::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?)
                            as u64;
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::DS) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::ES) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::FS) => {
                    saved.fs =
                        u32::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?)
                            as u64;
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::GS) => {
                    saved.gs =
                        u32::from_le_bytes(val.try_into().map_err(|e| TargetError::NonFatal)?)
                            as u64;
                }
                //X86_64CoreRegId::St(u8) => {},
                //X86_64CoreRegId::Fpu(X87FpuInternalRegId) => {},
                //X86_64CoreRegId::Xmm(u8) => {},
                //X86_64CoreRegId::Mxcsr => {},
                missing => {
                    error!("Unimplemented register {:?}", missing);
                    return Err(TargetError::NonFatal);
                }
            };

            Ok(())
        } else {
            Err(TargetError::NonFatal)
        }
    }
}

impl SectionOffsets for KernelDebugger {
    /// Tells GDB where in memory the bootloader has put our kernel binary.
    fn get_section_offsets(&mut self) -> Result<Offsets<u64>, KError> {
        let kcb = super::kcb::get_kcb();
        let boot_args = kcb.arch.kernel_args();
        let kernel_reloc_offset = boot_args.kernel_elf_offset.as_u64();

        Ok(Offsets::Sections {
            text: kernel_reloc_offset,
            data: kernel_reloc_offset,
            bss: None,
        })
    }
}

fn watchkind_to_breakcondition(kind: WatchKind) -> debugregs::BreakCondition {
    match kind {
        // There is no read-only break condition in x86
        WatchKind::Read => debugregs::BreakCondition::DataReadsWrites,
        WatchKind::Write => debugregs::BreakCondition::DataWrites,
        WatchKind::ReadWrite => debugregs::BreakCondition::DataReadsWrites,
    }
}

impl HwWatchpoint for KernelDebugger {
    fn add_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        info!("add hw watchpoint {:#x} {} {:?}", addr, len, kind);
        for (reg, entry) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
        {
            let bs = match len {
                1 => debugregs::BreakSize::Bytes1,
                2 => debugregs::BreakSize::Bytes2,
                4 => debugregs::BreakSize::Bytes4,
                8 => debugregs::BreakSize::Bytes8,
                _ => {
                    error!("Unsupported len argument provided by GDB: {}", len);
                    debugregs::BreakSize::Bytes8
                }
            };

            if entry.is_none() {
                *entry = Some((VAddr::from(addr), BreakType::Watchpoint(kind)));

                // Safety: We're in CPL0, can handle debug interrupt.
                unsafe {
                    // Set address in dr{0-3} register
                    debugregs::dr_write(*reg, addr.try_into().unwrap());
                    // Enable bp in dr7
                    let mut dr7 = debugregs::dr7();
                    let bc = watchkind_to_breakcondition(kind);
                    dr7.enable_bp(*reg, bc, bs, KernelDebugger::GLOBAL_BP_FLAG);
                    debugregs::dr7_write(dr7);
                }
                return Ok(true);
            }
        }

        error!("No more debug registers available for add_hw_watchpoint");
        Ok(false)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u64,
        _len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        for (reg, entry) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
        {
            if let Some((entry_vaddr, BreakType::Watchpoint(kind))) = entry {
                if entry_vaddr.as_u64() == addr {
                    unsafe {
                        debugregs::dr_write(*reg, 0x0);
                        let mut dr7 = debugregs::dr7();
                        dr7.disable_bp(*reg, KernelDebugger::GLOBAL_BP_FLAG);
                        debugregs::dr7_write(dr7);
                    }

                    *entry = None;
                    return Ok(true);
                }
            }
        }

        // No break point matching the address was found
        error!("Unable to remove hw watchpoint for addr {:#x}", addr);
        Ok(false)
    }
}

impl HwBreakpoint for KernelDebugger {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        trace!("add hw breakpoint {:#x}", addr);
        for (reg, entry) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
        {
            if entry.is_none() {
                *entry = Some((VAddr::from(addr), BreakType::Breakpoint));

                // Safety: We're in CPL0, can handle debug interrupt.
                unsafe {
                    // Set address in dr{0-3} register
                    debugregs::dr_write(*reg, addr.try_into().unwrap());
                    // Enable bp in dr7
                    let mut dr7 = debugregs::dr7();
                    dr7.enable_bp(
                        *reg,
                        debugregs::BreakCondition::Instructions,
                        // This has to be Bytes1 on x86 for instructions, so I
                        // think we can ignore the _kind arg
                        debugregs::BreakSize::Bytes1,
                        KernelDebugger::GLOBAL_BP_FLAG,
                    );
                    info!("added hw breakpoint {:#x}", addr);
                    debugregs::dr7_write(dr7);
                }
                return Ok(true);
            }
        }

        error!("No more debug registers available for add_hw_breakpoint");
        Ok(false)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        trace!("remove_hw_breakpoint {:#x}", addr);

        for (reg, entry) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
        {
            if let Some((entry_vaddr, BreakType::Breakpoint)) = entry {
                if entry_vaddr.as_u64() == addr {
                    unsafe {
                        debugregs::dr_write(*reg, 0x0);
                        let mut dr7 = debugregs::dr7();
                        dr7.disable_bp(*reg, KernelDebugger::GLOBAL_BP_FLAG);
                        debugregs::dr7_write(dr7);
                    }

                    *entry = None;
                    return Ok(true);
                }
            }
        }

        // No break point matching the address was found
        error!("Unable to remove hw breakpoint for addr {:#x}", addr);
        Ok(false)
    }
}
