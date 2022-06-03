// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::num::NonZeroUsize;

use gdbstub::common::Signal;
use gdbstub::state_machine::GdbStubStateMachine;
use gdbstub::target::ext::base::multithread::ThreadStopReason;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::BreakpointsOps;
use gdbstub::target::ext::section_offsets::SectionOffsetsOps;
use gdbstub::target::Target;
use gdbstub::{ConnectionExt, GdbStubError};
use gdbstub_arch::x86::X86_64_SSE;
use lazy_static::lazy_static;
use log::{debug, error, info, trace};
use spin::Mutex;
use x86::bits64::rflags::RFlags;
use x86::debugregs;

use super::debug::GDB_REMOTE_PORT;
use crate::error::KError;

mod breakpoints;
mod section_offsets;
mod serial;
mod single_register;
mod single_thread_ops;

use breakpoints::*;
use serial::*;

/// Indicates the reason for interruption (e.g. a breakpoint was hit).
#[allow(unused)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KCoreStopReason {
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
    /// We have received data on the (serial) line between us and gdb.
    ConnectionInterrupt,
}

lazy_static! {
    /// The GDB connection state machine.
    ///
    /// This is a state machine that handles the communication with the GDB.
    pub(crate) static ref GDB_STUB: Mutex<Option<(GdbStubStateMachine<'static, KernelDebugger, GdbSerial>, KernelDebugger)>> = {
        let connection = wait_for_gdb_connection(GDB_REMOTE_PORT).expect("Can't connect to GDB");
        let mut target = KernelDebugger::new();
        let gdb_stm = gdbstub::GdbStub::new(connection).run_state_machine(&mut target).expect("Can't start GDB session");
        Mutex::new(Some((gdb_stm, target)))
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
pub(crate) fn event_loop(reason: KCoreStopReason) -> Result<(), KError> {
    if GDB_STUB.is_locked() {
        panic!("re-entrant into event_loop!");
    }
    let (mut gdb_stm, mut target) = GDB_STUB.lock().take().unwrap();

    let mut stop_reason = target.determine_stop_reason(reason);
    debug!("event_loop stop_reason {:?}", stop_reason);
    loop {
        gdb_stm = match gdb_stm {
            GdbStubStateMachine::Idle(mut gdb_stm_inner) => {
                //trace!("GdbStubStateMachine::Idle");

                // This means we expect stuff on the serial line (from GDB)
                // Let's read and react to it:
                let conn = gdb_stm_inner.borrow_conn();
                conn.disable_irq();
                let byte = conn.read()?;

                match gdb_stm_inner.incoming_data(&mut target, byte) {
                    Ok(gdb) => gdb,
                    Err(GdbStubError::TargetError(e)) => {
                        error!("Debugger raised a fatal error {:?}", e);
                        break;
                    }
                    Err(e) => {
                        error!("gdbstub internal error {:?}", e);
                        break;
                    }
                }
            }
            GdbStubStateMachine::CtrlCInterrupt(gdb_stm_inner) => {
                match gdb_stm_inner.interrupt_handled(&mut target, Some(ThreadStopReason::DoneStep))
                {
                    Ok(gdb) => gdb,
                    Err(e) => {
                        error!("gdbstub error {:?}", e);
                        break;
                    }
                }
            }
            GdbStubStateMachine::Disconnected(_gdb_stm_inner) => {
                error!("GdbStubStateMachine::Disconnected byebye");
                break;
            }
            GdbStubStateMachine::Running(mut gdb_stm_inner) => {
                //trace!("GdbStubStateMachine::DeferredStopReason");

                // If we're here we were running but have stopped now (either
                // because we hit Ctrl+c in gdb and hence got a serial interrupt
                // or we hit a breakpoint).
                let conn = gdb_stm_inner.borrow_conn();
                conn.disable_irq();
                let data_to_read = conn.peek().unwrap().is_some();

                if data_to_read {
                    let byte = gdb_stm_inner.borrow_conn().read().unwrap();
                    match gdb_stm_inner.incoming_data(&mut target, byte) {
                        Ok(pumped_stm) => pumped_stm,
                        Err(GdbStubError::TargetError(e)) => {
                            error!("Target raised a fatal error: {:?}", e);
                            break;
                        }
                        Err(e) => {
                            error!("gdbstub error in DeferredStopReason.pump: {:?}", e);
                            break;
                        }
                    }
                } else if let Some(reason) = stop_reason.take() {
                    match gdb_stm_inner.report_stop(&mut target, reason) {
                        Ok(gdb_stm_new) => gdb_stm_new,
                        Err(GdbStubError::TargetError(e)) => {
                            error!("Target raised a fatal error {:?}", e);
                            break;
                        }
                        Err(e) => {
                            error!("gdbstub internal error {:?}", e);
                            break;
                        }
                    }
                } else if target.resume_with.is_some() {
                    // We don't have a `stop_reason` and we don't have something
                    // to read on the line. This probably means we're done and
                    // we should run again.
                    match target.resume_with.take() {
                        Some(ExecMode::Continue) => {
                            //trace!("Resume execution.");
                            let kcb = super::kcb::get_kcb();
                            // If we were stepping, we need to remove the TF bit again for resuming
                            if let Some(saved) = &mut kcb.save_area {
                                let mut rflags = RFlags::from_bits_truncate(saved.rflags);
                                rflags.remove(x86::bits64::rflags::RFlags::FLAGS_TF);
                                saved.rflags = rflags.bits();
                            }
                        }
                        Some(ExecMode::SingleStep) => {
                            trace!("Step execution, set TF flag.");
                            let kcb = super::kcb::get_kcb();
                            if let Some(saved) = &mut kcb.save_area {
                                saved.rflags |= RFlags::FLAGS_TF.bits();
                            }
                        }
                        _ => {
                            unimplemented!("Resume strategy not handled...");
                        }
                    }
                    conn.enable_irq();
                    let r = GDB_STUB
                        .lock()
                        .replace((GdbStubStateMachine::Running(gdb_stm_inner), target));
                    assert!(
                        r.is_none(),
                        "Put something in GDB_STUB which we shouldn't have..."
                    );
                    break;
                } else {
                    unreachable!("Can't happen?");
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExecMode {
    /// Continue program unconditionally
    Continue,
    SingleStep,
}

/// A kernel level debug implementation that can interface with GDB over remote
/// serial protocol.
pub(crate) struct KernelDebugger {
    /// Maintains meta-data about our hardware breakpoint registers.
    hw_break_points: [Option<BreakState>; 4],
    /// Resume program with this signal (if needed).
    _signal: Option<Signal>,
    /// How we resume the program (set by gdbstub in resume or step).
    resume_with: Option<ExecMode>,
}

impl KernelDebugger {
    pub(crate) fn new() -> Self {
        Self {
            hw_break_points: [None; 4],
            resume_with: None,
            _signal: None,
        }
    }

    /// Figures out why a core got a debug interrupt by looking through the
    /// hardware debug register and reading which one was hit.
    ///
    // Also does some additional stuff like re-enabling the breakpoints.
    fn determine_stop_reason(&mut self, reason: KCoreStopReason) -> Option<ThreadStopReason<u64>> {
        match reason {
            KCoreStopReason::ConnectionInterrupt => Some(ThreadStopReason::Signal(Signal::SIGTRAP)),
            KCoreStopReason::BreakpointInterrupt => {
                unimplemented!("Breakpoint interrupt not implemented");
                //Some(ThreadStopReason::SwBreak(NonZeroUsize::new(1).unwrap()))
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
                let stop: Option<ThreadStopReason<u64>> = if let Some(BreakState(
                    _va,
                    BreakType::Breakpoint,
                    BreakRequest::Hardware,
                )) = bp
                {
                    Some(ThreadStopReason::HwBreak(NonZeroUsize::new(1).unwrap()))
                } else if let Some(BreakState(_va, BreakType::Breakpoint, BreakRequest::Software)) =
                    bp
                {
                    Some(ThreadStopReason::SwBreak(NonZeroUsize::new(1).unwrap()))
                } else if let Some(BreakState(
                    va,
                    BreakType::Watchpoint(kind),
                    BreakRequest::Hardware,
                )) = bp
                {
                    Some(ThreadStopReason::Watch {
                        tid: NonZeroUsize::new(1).unwrap(),
                        kind,
                        addr: va.as_u64(),
                    })
                } else if let Some(BreakState(
                    _va,
                    BreakType::Watchpoint(_kind),
                    BreakRequest::Software,
                )) = bp
                {
                    unimplemented!("Shouldn't have ever set a software watchpoint!")
                } else if dr6.contains(debugregs::Dr6::BS) {
                    // When the BS flag is set, any of the other debug status bits also may be set.
                    dr6.remove(debugregs::Dr6::BS);
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

    fn support_section_offsets(&mut self) -> Option<SectionOffsetsOps<Self>> {
        Some(self)
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }

    fn use_x_upcase_packet(&self) -> bool {
        true
    }
}
