// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Defines the public kernel interface that is specific to x86-64.

#![allow(unaligned_references)]

use core::fmt;
use core::ops::Range;

pub mod syscalls;

pub use armv8::aarch64::vm::granule4k::{PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

use armv8::aarch64::vm::granule4k::*;

/// Start of the kernel address space.
pub const KERNEL_BASE: u64 = 0xffff_0000_0000_0000;

pub const ROOT_TABLE_SLOT_SIZE: usize = L1_TABLE_ENTRIES * HUGE_PAGE_SIZE;

/// The virtual CPU is a shared data-structure between the kernel and user-space
/// that facilitates IRQ/trap delivery and emulation of critical sections
/// for a user-space scheduler.
///
/// # Important
/// This struct is referenced by several assembly code pieces through the kernel
/// and in [vibrio]. Care must be taken to adjust them after any changes to
/// this struct.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct VirtualCpu {
    /// CPU state if interrupted while not disabled
    pub enabled_state: SaveArea,
    /// PC critical region
    pub pc_disabled: (VAddr, VAddr),
    /// Function pointer to the entry point for upcalls.
    pub resume_with_upcall: VAddr,
    /// Are we in a critical section?
    pub is_disabled: bool,
    /// An upcall needs to be executed.
    pub has_pending_upcall: bool,
}

impl VirtualCpu {
    /// Is the vCPU currently disabled or executing in a critical section?
    pub fn upcalls_disabled(&self, rip: VAddr) -> bool {
        self.is_disabled || self.pc_disabled.0 <= rip && rip <= self.pc_disabled.1
    }

    pub fn enable_upcalls(&mut self) {
        self.is_disabled = false;
    }

    pub fn disable_upcalls(&mut self) {
        self.is_disabled = true;
    }
}

/// Memory area that is used by a CPU/scheduler to capture and save
/// the current CPU register state.
///
/// # Important
/// This struct is referenced by several assembly code pieces through the kernel
/// and in [vibrio]. Care must be taken to adjust them after any changes to
/// this struct.
/// Grep for SaveArea to find all occurences.
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct SaveArea {
    /// General purpose registers
    ///
    /// x30      LR  The Link Register.
    /// x29      FP  The Frame Pointer
    /// x19…x28  Callee-saved registers
    /// x18      The Platform Register, if needed; otherwise a temporary register. See notes.
    /// r17      The second intra-procedure-call temporary register (can be used by call veneers and PLT code); at other times may be used as a temporary register.
    /// r16      The first intra-procedure-call scratch register (can be used by call veneers and PLT code); at other times may be used as a temporary register.
    /// r9…r15   Temporary registers
    /// r8       Indirect result location register
    /// r0…r7    Parameter/result registers
    pub x: [u64; 31],
    /// the stack pointer register
    pub sp: u64,
    /// the program counter
    pub pc: u64,
    /// the saved processor status register
    pub spsr: u64,
    /// the saved user writable thread id register
    pub tpidr: u64,

    _padding: u64,
    /// floating point registers (32x128 bits)
    pub v: [u128; 32],
}

static_assertions::const_assert_eq!(memoffset::offset_of!(SaveArea, sp), 31 * 8);
static_assertions::const_assert_eq!(memoffset::offset_of!(SaveArea, pc), 32 * 8);
static_assertions::const_assert_eq!(memoffset::offset_of!(SaveArea, spsr), 33 * 8);
static_assertions::const_assert_eq!(memoffset::offset_of!(SaveArea, tpidr), 34 * 8);
static_assertions::const_assert_eq!(memoffset::offset_of!(SaveArea, v), 36 * 8);

impl SaveArea {
    pub fn empty() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            spsr: 0,
            tpidr: 0,
            _padding: 0,
            v: [0; 32],
        }
    }

    pub fn set_syscall_error_code(&mut self, err: crate::SystemCallError) {
        self.x[0] = err as u64;
    }

    pub fn set_syscall_ret0(&mut self, a: u64) {
        self.x[0] = a;
    }

    pub fn set_syscall_ret1(&mut self, a: u64) {
        self.x[1] = a;
    }

    pub fn set_syscall_ret2(&mut self, a: u64) {
        self.x[2] = a;
    }

    pub fn set_syscall_ret3(&mut self, a: u64) {
        self.x[3] = a;
    }

    /// sets the frame pointer register
    pub fn set_fp(&self) -> u64 {
        self.x[29]
    }

    /// obtains the frame pointer register
    pub fn get_fp(&self) -> u64 {
        self.x[29]
    }

    /// sets the link registers
    pub fn set_lr(&mut self, lr: u64) {
        self.x[30] = lr;
    }

    /// obtains the link register
    pub fn get_lr(&self) -> u64 {
        self.x[30]
    }

    pub fn set_spsr(&mut self, spsr: u64) {
        self.spsr = spsr;
    }

    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    pub fn set_sp(&mut self, sp: u64) {
        self.sp = sp;
    }
}

impl Default for SaveArea {
    fn default() -> SaveArea {
        SaveArea::empty()
    }
}

impl fmt::Debug for SaveArea {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f,"Save Area: ");
        for i in 0..29 {
            writeln!(f, "  x{:02}    = 0x{:016x}", i, self.x[i])?;
        }
        writeln!(f, "  fp    = 0x{:016x}", self.x[29])?;
        writeln!(f, "  lr    = 0x{:016x}", self.x[30])?;
        writeln!(f, "  sp    = 0x{:016x}", self.sp)?;
        writeln!(f, "  pc    = 0x{:016x}", self.pc)?;
        writeln!(f, "  spsr  = 0x{:016x}", self.spsr)?;
        writeln!(f, "  tpidr = 0x{:016x}", self.tpidr)
    }

}
