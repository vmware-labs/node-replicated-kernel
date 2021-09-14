// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Defines the public kernel interface that is specific to x86-64.

#![allow(unaligned_references)]

use core::fmt;

use x86::bits64::paging::VAddr;
use x86::bits64::rflags::RFlags;

/// The virtual CPU is a shared data-structure between the kernel and user-space
/// that facilitates IRQ/trap delivery and emulation of critical sections
/// for a user-space scheduler.
///
/// # Important
/// This struct is referenced by several assembly code pieces through the kernel
/// and in [vibrio]. Care must be taken to adjust them after any changes to
/// this struct.
#[repr(C, packed)]
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
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SaveArea {
    /// 0: ret val, not preserved, holds 1st ret arg (error code)
    /// for syscalls
    pub rax: u64,
    /// 1: preserved
    pub rbx: u64,
    /// 2: 4th arg, not preserved
    pub rcx: u64,
    /// 3: 3rd arg, not preserved, holds return %rip during a syscall
    pub rdx: u64,
    /// 4: 2nd arg, not preserved
    /// 3nd return argument on sysretq
    pub rsi: u64,
    /// 5: 1st arg, not preserved
    /// 2nd return argument on sysretq
    pub rdi: u64,
    /// 6: base pointer, preserved, holds 2nd ret arg for syscall
    pub rbp: u64,
    /// 7: stack pointer, preserved
    pub rsp: u64,
    /// 8: 5th arg, not preserved
    pub r8: u64,
    /// 9: 6th arg, not preserved
    pub r9: u64,
    /// 10: not preserved, temporary substitute for rcx when doing a syscall
    pub r10: u64,
    /// 11: not preserved, holds user RFlags during a syscall
    pub r11: u64,
    /// 12: preserved
    pub r12: u64,
    /// 13: preserved
    pub r13: u64,
    /// 14: preserved
    pub r14: u64,
    /// 15: preserved
    pub r15: u64,
    /// 16: instruction pointer
    pub rip: u64,
    /// 17: RFlags
    pub rflags: u64,
    /// 18: %gs register
    pub gs: u64,
    /// 19: %fs register
    pub fs: u64,
    /// 20: Vector in case of interruption
    pub vector: u64,
    /// 21: Error code in case of interruption
    pub exception: u64,
    /// 22: %cs register
    pub cs: u64,
    /// 23: %ss register
    pub ss: u64,
    /// 24: Floating point register state
    pub fxsave: [u8; 512],
}

impl Default for SaveArea {
    fn default() -> SaveArea {
        SaveArea::empty()
    }
}

impl SaveArea {
    pub const fn empty() -> SaveArea {
        SaveArea {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            fs: 0,
            gs: 0,
            vector: 0,
            exception: 0,
            cs: 0,
            ss: 0,
            fxsave: [0; 512],
        }
    }

    /// Sets the error return code on a system call.
    ///
    /// 0th argument is passed back in the rax register.
    pub fn set_syscall_error_code(&mut self, err: crate::SystemCallError) {
        self.rax = err as u64;
    }

    /// Sets the 1st return argument for system calls
    ///
    /// 1st argument is passed back in the rdi register.
    pub fn set_syscall_ret1(&mut self, val: u64) {
        self.rdi = val;
    }

    /// Sets the 2nd return argument for system calls
    ///
    /// 2nd argument is passed back in the rsi register.
    pub fn set_syscall_ret2(&mut self, val: u64) {
        self.rsi = val;
    }
}

impl fmt::Debug for SaveArea {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SaveArea\r\n
rax = {:>#18x} rbx = {:>#18x} rcx = {:>#18x} rdx = {:>#18x}
rsi = {:>#18x} rdi = {:>#18x} rbp = {:>#18x} rsp = {:>#18x}
r8  = {:>#18x} r9  = {:>#18x} r10 = {:>#18x} r11 = {:>#18x}
r12 = {:>#18x} r13 = {:>#18x} r14 = {:>#18x} r15 = {:>#18x}
rip = {:>#18x} rflags = {:?}",
            self.rax,
            self.rbx,
            self.rcx,
            self.rdx,
            self.rsi,
            self.rdi,
            self.rbp,
            self.rsp,
            self.r8,
            self.r9,
            self.r10,
            self.r11,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.rip,
            RFlags::from_raw(self.rflags)
        )
    }
}
