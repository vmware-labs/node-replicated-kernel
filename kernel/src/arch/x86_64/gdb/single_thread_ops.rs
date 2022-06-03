// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryInto;

use gdbstub::common::Signal;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadOps, SingleThreadSingleStep, SingleThreadSingleStepOps,
};
use gdbstub::target::ext::base::SingleRegisterAccessOps;
use gdbstub::target::{TargetError, TargetResult};
use log::{debug, error, info, trace, warn};

use super::super::vspace::page_table::ReadOnlyPageTable;
use super::{ExecMode, KernelDebugger};
use crate::memory::vspace::AddressSpace;
use crate::memory::{VAddr, BASE_PAGE_SIZE};
use kpi::arch::ST_REGS;

impl SingleThreadOps for KernelDebugger {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        assert!(signal.is_none(), "Not supported at the moment.");

        self._signal = signal;
        self.resume_with = Some(ExecMode::Continue);
        trace!(
            "resume: signal = {:?} resume_with =  {:?}",
            signal,
            self.resume_with
        );

        // If the target is running under the more advanced GdbStubStateMachine
        // API, it is possible to "defer" reporting a stop reason to some point
        // outside of the resume implementation by returning None.
        Ok(())
    }

    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::x86::reg::X86_64CoreRegs,
    ) -> TargetResult<(), Self> {
        let kcb = super::super::kcb::get_kcb();
        if let Some(saved) = &kcb.save_area {
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
                // fs should be saved.fs.try_into().unwrap() -- but why is this
                // gdb type a u32 but with rdfsbase this can be 64bit and so
                // panics here? maybe I'm not supposed to store fsbase here?
                fs: 0x0,
                gs: saved.gs.try_into().unwrap(), // see same as fs
            };

            // FPU registers: ST0 through ST7
            for (i, reg) in ST_REGS.iter().enumerate() {
                regs.st[i] = saved.fxsave.st(*reg);
            }

            // FPU internal registers
            regs.fpu.fctrl = saved.fxsave.fcw.try_into().unwrap();
            regs.fpu.fstat = saved.fxsave.fsw.try_into().unwrap();
            regs.fpu.ftag = saved.fxsave.ftw.try_into().unwrap();
            regs.fpu.fiseg = saved.fxsave.fcs.try_into().unwrap();
            regs.fpu.fioff = saved.fxsave.fip.try_into().unwrap();
            regs.fpu.foseg = saved.fxsave.fds.try_into().unwrap();
            regs.fpu.fooff = saved.fxsave.fdp.try_into().unwrap();
            regs.fpu.fop = saved.fxsave.fop.try_into().unwrap();

            // SIMD Registers: XMM0 through XMM15
            regs.xmm = saved.fxsave.xmm;

            // SSE Status/Control Register
            regs.mxcsr = saved.fxsave.mxcsr;
        }

        trace!("read_registers {:02X?}", regs);
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::x86::reg::X86_64CoreRegs,
    ) -> TargetResult<(), Self> {
        trace!("write_registers {:?}", regs);
        let kcb = super::super::kcb::get_kcb();
        if let Some(saved) = &mut kcb.save_area {
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

            // FPU registers: ST0 through ST7
            for (_i, _reg) in ST_REGS.iter().enumerate() {
                //regs.st[i] = saved.fxsave.st(*reg);
            }

            // FPU internal registers
            saved.fxsave.fcw = regs.fpu.fctrl.try_into().unwrap();
            saved.fxsave.fsw = regs.fpu.fstat.try_into().unwrap();
            saved.fxsave.ftw = regs.fpu.ftag.try_into().unwrap();
            saved.fxsave.fcs = regs.fpu.fiseg.try_into().unwrap();
            saved.fxsave.fip = regs.fpu.fioff.try_into().unwrap();
            saved.fxsave.fds = regs.fpu.foseg.try_into().unwrap();
            saved.fxsave.fdp = regs.fpu.fooff.try_into().unwrap();
            saved.fxsave.fop = regs.fpu.fop.try_into().unwrap();

            // SIMD Registers: XMM0 through XMM15
            saved.fxsave.xmm = regs.xmm;

            // SSE Status/Control Register
            saved.fxsave.mxcsr = regs.mxcsr;
        }
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<(), Self> {
        trace!("read_addr {:#x}", start_addr);
        // (Un)Safety: Well, this can easily violate the rust aliasing model
        // because when we arrive in the debugger; there might some mutable
        // reference to the PTs somewhere in a context that was modifying the
        // PTs. We'll just have to accept this for debugging.
        let pt = unsafe { ReadOnlyPageTable::current() };

        let start_addr: usize = start_addr.try_into().unwrap();
        if !kpi::arch::VADDR_RANGE.contains(&start_addr) {
            warn!("Address out of range {}", start_addr);
            return Err(TargetError::NonFatal);
        }

        for i in 0..data.len() {
            let va = VAddr::from(start_addr + i);

            // Check access rights for start of every new page we encounter (and
            // for the first byte that might start within a page)
            if i == 0 || (start_addr + i) % BASE_PAGE_SIZE == 0 {
                match pt.resolve(va) {
                    Ok((_pa, rights)) => {
                        if !rights.is_readable() {
                            // Mapped but not read-able (this can't really happen would mean
                            // something like swapped out but we don't do that)
                            return Err(TargetError::NonFatal);
                        }
                    }
                    Err(_) => {
                        warn!("Target page was not mapped.");
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
        trace!("write_addrs {:#x}", start_addr);

        // (Un)Safety: Well, this can easily violate the rust aliasing model
        // because when we arrive in the debugger; there might some mutable
        // reference to the PTs somewhere in a context that was modifying the
        // PTs. We'll just have to accept this for debugging.
        let pt = unsafe { ReadOnlyPageTable::current() };

        let start_addr: usize = start_addr.try_into().unwrap();
        for (i, payload) in data.iter().enumerate() {
            let va = VAddr::from(start_addr + i);

            // Check access rights for start of every new page that we encounter
            // (and for the first byte that might start within a page)
            if i == 0 || (start_addr + i) % BASE_PAGE_SIZE == 0 {
                if !kpi::arch::VADDR_RANGE.contains(&start_addr) {
                    warn!("Address out of range {}", start_addr);
                    return Err(TargetError::NonFatal);
                }

                match pt.resolve(va) {
                    Ok((_pa, rights)) => {
                        // Not implemented: We don't allow writing in executable
                        // `.text`. This gives some warnings in gdb because it
                        // tries to set breakpoints by writing `int 3` in random
                        // code location. This currently doesn't work, either
                        // because we don't adjust the rip properly or don't
                        // implement the swbreak function or it's generally bad
                        // to overwrite code that is potentially used by the
                        // gdbstub functionality too (like what happens if you
                        // set a breakpoint in the log crate)
                        //
                        // I believe gdb falls back to stepping if the returns
                        // NonFatal.
                        if rights.is_executable() {
                            error!("Can't write to executable page.");
                            error!("If you were trying to set a breakpoint use `hbreak` instead of `break`");
                            return Err(TargetError::NonFatal);
                        }
                        if !rights.is_writable() {
                            debug!("Target page mapped as read-only. Can't write at address.");
                            return Err(TargetError::NonFatal);
                        }
                    }
                    Err(_) => {
                        // Target page was not mapped
                        warn!("Target page not mapped.");
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

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<(), Self>> {
        //Some(self)
        None
    }

    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<Self>> {
        Some(self)
        //None
    }
}

/// Adds `gdbstub` support for single-stepping.
impl SingleThreadSingleStep for KernelDebugger {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        assert!(signal.is_none(), "Not supported at the moment.");

        self._signal = signal;
        self.resume_with = Some(ExecMode::SingleStep);
        info!(
            "set signal = {:?} resume_with =  {:?}",
            signal, self.resume_with
        );

        Ok(())
    }
}
