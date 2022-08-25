// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Defines the public kernel interface that is specific to x86-64.

#![allow(unaligned_references)]

use core::fmt;
use core::ops::Range;

use armv8::aarch64::vm::granule4k::*;

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
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub spsr: u64,
    pub v: [u128; 32],
}

impl SaveArea {
    /// sets the frame pointer register
    pub fn set_fp(&self) -> u64 {
        self.x[30]
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
}

impl fmt::Debug for SaveArea {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SaveArea {{ x: {:?}, sp: {:?}, pc: {:?}, spsr: {:?}, v: {:?} }}",
            self.x, self.sp, self.pc, self.spsr, self.v
        )
    }
}