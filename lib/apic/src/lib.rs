// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![feature(core_intrinsics)]

use x86::apic::{ApicId, Icr};

pub const TSC_TIMER_VECTOR: u8 = 252;

pub mod x2apic;
pub mod xapic;

/// Abstracts common interface of local APIC (x2APIC, xAPIC) drivers.
pub trait ApicDriver {
    /// Is a bootstrap processor?
    fn bsp(&self) -> bool;

    /// Return APIC ID.
    fn id(&self) -> u32;

    /// Return the logical APIC ID.
    fn logical_id(&self) -> u32;

    /// Read APIC version
    fn version(&self) -> u32;

    /// End Of Interrupt -- Acknowledge interrupt delivery.
    fn eoi(&mut self);

    /// Enable TSC deadline timer.
    fn tsc_enable(&mut self);

    /// Set TSC deadline value.
    fn tsc_set(&self, value: u64);

    /// Send a INIT IPI to a core.
    ///
    /// # Safety
    /// This can reset a core.
    unsafe fn ipi_init(&mut self, core: ApicId);

    /// Deassert INIT IPI.
    ///
    /// # Safety
    /// This can reset a core.
    unsafe fn ipi_init_deassert(&mut self);

    /// Send a STARTUP IPI to a core.
    ///
    /// # Safety
    /// This can reset a core.
    unsafe fn ipi_startup(&mut self, core: ApicId, start_page: u8);

    /// Send a generic IPI.
    ///
    /// # Safety
    /// Triggers an IPI on a remote core(s) and can easily crash them by sending
    /// to the wrong core, or the wrong vector etc.
    unsafe fn send_ipi(&mut self, icr: Icr);
}
