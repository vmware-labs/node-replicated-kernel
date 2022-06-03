// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::memory::VAddr;
use bit_field::BitField;
use core::convert::TryInto;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps, SwBreakpoint,
    SwBreakpointOps, WatchKind,
};
use gdbstub::target::TargetResult;
use log::{info, trace, warn};
use x86::debugregs;

use super::KernelDebugger;

/// What kind of breakpoint GDB is trying to set.
///
/// Heads-up we're using a hardware breakpoint either way. But we need to return
/// the right gdb error code when we hit a BP so we keep track of what GDB
/// requested.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BreakRequest {
    /// GDB requested a hardware breakpoint.
    Hardware,
    /// GDB requested a software breakpoint.
    Software,
}

/// What kind of breakpoint it is.
///
/// Watch memory location or instruction pointer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BreakType {
    /// For instructions
    Breakpoint,
    /// For data access/writes
    Watchpoint(WatchKind),
}

/// Keeps information about any breakpoints we've set.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct BreakState(pub VAddr, pub BreakType, pub BreakRequest);

impl KernelDebugger {
    pub(super) fn add_breakpoint(
        &mut self,
        req: BreakRequest,
        addr: u64,
        _kind: usize,
    ) -> TargetResult<bool, Self> {
        let kernel_elf_offset = crate::KERNEL_ARGS
            .get()
            .map_or(0x0, |args| args.kernel_elf_offset.as_u64());
        trace!(
            "add_breakpoint {:#x} (in ELF: {:#x})",
            addr,
            addr - kernel_elf_offset,
        );

        let kcb = super::super::kcb::get_kcb();
        let sa = kcb.save_area.as_mut().expect("Need to have a save area");

        for (idx, (reg, entry)) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
            .enumerate()
        {
            if entry.is_none() {
                *entry = Some(BreakState(VAddr::from(addr), BreakType::Breakpoint, req));

                // Safety: We're in CPL0.
                //
                // TODO: For more safety we should sanitize the address to make
                // sure we can't set it inside certain regions (on code that is
                // used by the gdb module etc.)
                unsafe {
                    // break size has to be Bytes1 on x86 for instructions, so I
                    // think we can ignore the `_kind` arg
                    reg.configure(
                        addr.try_into().unwrap(),
                        debugregs::BreakCondition::Instructions,
                        debugregs::BreakSize::Bytes1,
                    );
                }

                // Don't enable the BP, but mark register as "to enable" for the
                // context restore logic:
                sa.enabled_bps.set_bit(idx, true);
                info!("sa.enabled_bps {:#b}", sa.enabled_bps);
                return Ok(true);
            }
        }

        warn!("No more debug registers available for add_hw_breakpoint");
        Ok(false)
    }

    pub(super) fn remove_breakpoint(
        &mut self,
        req: BreakRequest,
        addr: u64,
        _kind: usize,
    ) -> TargetResult<bool, Self> {
        let kernel_elf_offset = crate::KERNEL_ARGS
            .get()
            .map_or(0x0, |args| args.kernel_elf_offset.as_u64());
        trace!(
            "remove_breakpoint {:#x} (in ELF: {:#x}",
            addr,
            addr - kernel_elf_offset,
        );

        let kcb = super::super::kcb::get_kcb();
        let sa = kcb.save_area.as_mut().expect("Need to have a save area");

        for (idx, (reg, entry)) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
            .enumerate()
        {
            if let Some(BreakState(entry_addr, BreakType::Breakpoint, entry_req)) = entry {
                if entry_addr.as_u64() == addr && *entry_req == req {
                    unsafe {
                        reg.disable_global();
                    }
                    *entry = None;
                    sa.enabled_bps.set_bit(idx, false);
                    return Ok(true);
                }
            }
        }

        // No break point matching the address was found
        warn!("Unable to remove hw breakpoint for addr {:#x}", addr);
        Ok(false)
    }
}

/// Tell gdbstub we do support breakpoints.
impl Breakpoints for KernelDebugger {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<Self>> {
        Some(self)
    }

    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<Self>> {
        Some(self)
    }
}

/// Helper function to convert gdbstub `WatchKind` to x86 `debugregs::BreakCondition`.
fn watchkind_to_breakcondition(kind: WatchKind) -> debugregs::BreakCondition {
    match kind {
        // There is no read-only break condition in x86
        WatchKind::Read => debugregs::BreakCondition::DataReadsWrites,
        WatchKind::Write => debugregs::BreakCondition::DataWrites,
        WatchKind::ReadWrite => debugregs::BreakCondition::DataReadsWrites,
    }
}

/// Implement SwBreakpoint for the kernel debugger.
impl SwBreakpoint for KernelDebugger {
    fn add_sw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
        trace!("add sw breakpoint {:#x}", addr);
        self.add_breakpoint(BreakRequest::Software, addr, kind)
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
        trace!("remove sw breakpoint {:#x}", addr);
        self.remove_breakpoint(BreakRequest::Software, addr, kind)
    }
}

/// Implement HwBreakpoint for the kernel debugger.
impl HwBreakpoint for KernelDebugger {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.add_breakpoint(BreakRequest::Hardware, addr, _kind)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.remove_breakpoint(BreakRequest::Hardware, addr, _kind)
    }
}

/// Implement Watchpoints for the kernel debugger.
impl HwWatchpoint for KernelDebugger {
    fn add_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        trace!("add_hw_watchpoint {:#x} {} {:?}", addr, len, kind);
        let sa = super::super::kcb::get_kcb()
            .save_area
            .as_mut()
            .expect("Need to have a save area");

        for (idx, (reg, entry)) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
            .enumerate()
        {
            let bs = match len {
                1 => debugregs::BreakSize::Bytes1,
                2 => debugregs::BreakSize::Bytes2,
                4 => debugregs::BreakSize::Bytes4,
                8 => debugregs::BreakSize::Bytes8,
                _ => {
                    warn!("Unsupported len ({}) provided by GDB, use 8 bytes.", len);
                    debugregs::BreakSize::Bytes8
                }
            };

            if entry.is_none() {
                *entry = Some(BreakState(
                    VAddr::from(addr),
                    BreakType::Watchpoint(kind),
                    BreakRequest::Hardware,
                ));
                let bc = watchkind_to_breakcondition(kind);

                // Safety: We're in CPL0.
                //
                // TODO: For more safety we should sanitize the address to make
                // sure we can't set it inside certain regions (on code that is
                // used by the gdb module etc.)
                unsafe {
                    reg.configure(addr.try_into().unwrap(), bc, bs);
                }
                sa.enabled_bps.set_bit(idx, true);
                info!("sa.enabled_bps {:#b}", sa.enabled_bps);

                return Ok(true);
            }
        }

        warn!("No more debug registers available for add_hw_watchpoint");
        Ok(false)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u64,
        _len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        trace!("remove_hw_watchpoint {:#x} {} {:?}", addr, _len, kind);
        let sa = super::super::kcb::get_kcb()
            .save_area
            .as_mut()
            .expect("Need to have a save area");

        for (idx, (reg, entry)) in debugregs::BREAKPOINT_REGS
            .iter()
            .zip(self.hw_break_points.iter_mut())
            .enumerate()
        {
            if let Some(BreakState(entry_vaddr, BreakType::Watchpoint(_kind), entry_req)) = entry {
                if entry_vaddr.as_u64() == addr && *entry_req == BreakRequest::Hardware {
                    unsafe { reg.disable_global() }
                    sa.enabled_bps.set_bit(idx, false);
                    info!("sa.enabled_bps {:#b}", sa.enabled_bps);

                    *entry = None;
                    return Ok(true);
                }
            }
        }

        // No break point matching the address was found
        warn!("Unable to remove hw watchpoint for addr {:#x}", addr);
        Ok(false)
    }
}
