#![allow(warnings)]

use core::convert::TryInto;

use log::{debug, error, info, trace, warn};

use gdbstub::common::{Signal, Tid};
use gdbstub::target;
use gdbstub::target::ext::base::multithread::{MultiThreadOps, MultiThreadSingleStep};
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::{Target, TargetError, TargetResult};

use super::{ExecMode, KernelDebugger};
use crate::error::KError;
use crate::memory::vspace::AddressSpace;
use crate::memory::{VAddr, BASE_PAGE_SIZE};

impl MultiThreadOps for KernelDebugger {
    fn resume(&mut self) -> Result<(), Self::Error> {
        // Upon returning from the `resume` method, the target being debugged should be
        // configured to run according to whatever resume actions the GDB client has
        // specified (as specified by `set_resume_action`, `set_resume_range_step`,
        // `set_reverse_{step, continue}`, etc...)
        //
        // In this basic `armv4t_multicore` example, the `resume` method is actually a
        // no-op, as the execution mode of the emulator's interpreter loop has already
        // been modified via the various `set_X` methods.
        //
        // In more complex implementations, it's likely that the target being debugged
        // will be running in another thread / process, and will require some kind of
        // external "orchestration" to set it's execution mode (e.g: modifying the
        // target's process state via platform specific debugging syscalls).

        Ok(())
    }

    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        //self.exec_mode.clear();
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<target::ext::base::multithread::MultiThreadSingleStepOps<Self>> {
        Some(self)
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        /*if signal.is_some() {
            return Err(KError::Unknown);
        }

        self.exec_mode
        .insert(tid_to_cpuid(tid)?, ExecMode::Continue);*/

        Ok(())
    }

    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::x86::reg::X86_64CoreRegs,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        /*
        let cpu = match tid_to_cpuid(tid).map_err(TargetError::Fatal)? {
            CpuId::Cpu => &mut self.cpu,
            CpuId::Cop => &mut self.cop,
        };

        let mode = cpu.mode();

        for i in 0..13 {
            regs.r[i] = cpu.reg_get(mode, i as u8);
        }
        regs.sp = cpu.reg_get(mode, reg::SP);
        regs.lr = cpu.reg_get(mode, reg::LR);
        regs.pc = cpu.reg_get(mode, reg::PC);
        regs.cpsr = cpu.reg_get(mode, reg::CPSR);*/

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::x86::reg::X86_64CoreRegs,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        /*let cpu = match tid_to_cpuid(tid).map_err(TargetError::Fatal)? {
                    CpuId::Cpu => &mut self.cpu,
                    CpuId::Cop => &mut self.cop,
                };

                let mode = cpu.mode();

                for i in 0..13 {
                    cpu.reg_set(mode, i, regs.r[i as usize]);
                }
                cpu.reg_set(mode, reg::SP, regs.sp);
                cpu.reg_set(mode, reg::LR, regs.lr);
                cpu.reg_set(mode, reg::PC, regs.pc);
                cpu.reg_set(mode, reg::CPSR, regs.cpsr);
        */
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: u64,
        data: &mut [u8],
        _tid: Tid, // same address space for each core
    ) -> TargetResult<(), Self> {
        /*for (addr, val) in (start_addr..).zip(data.iter_mut()) {
            *val = self.mem.r8(addr)
        }*/
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: u64,
        data: &[u8],
        _tid: Tid, // same address space for each core
    ) -> TargetResult<(), Self> {
        /*for (addr, val) in (start_addr..).zip(data.iter().copied()) {
            self.mem.w8(addr, val)
        }*/
        Ok(())
    }

    fn list_active_threads(
        &mut self,
        register_thread: &mut dyn FnMut(Tid),
    ) -> Result<(), Self::Error> {
        //register_thread(cpuid_to_tid(CpuId::Cpu));
        //register_thread(cpuid_to_tid(CpuId::Cop));
        Ok(())
    }
}

/// Adds `gdbstub` support for single-stepping.
impl MultiThreadSingleStep for KernelDebugger {
    fn set_resume_action_step(
        &mut self,
        _tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        assert!(signal.is_none(), "Not supported at the moment.");

        self._signal = signal;
        self.resume_with = Some(ExecMode::SingleStep);
        info!(
            "SingleThreadSingleStep::step: set signal = {:?} resume_with =  {:?}",
            signal, self.resume_with
        );

        Ok(())
    }
}
