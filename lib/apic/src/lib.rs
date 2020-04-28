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

    /// Read APIC version
    fn version(&self) -> u32;

    /// End Of Interrupt -- Acknowledge interrupt delivery.
    fn eoi(&mut self);

    /// Enable TSC deadline timer.
    fn tsc_enable(&mut self);

    /// Set TSC deadline value.
    fn tsc_set(&self, value: u64);

    /// Send a INIT IPI to a core.
    unsafe fn ipi_init(&mut self, core: ApicId);

    /// Deassert INIT IPI.
    unsafe fn ipi_init_deassert(&mut self);

    /// Send a STARTUP IPI to a core.
    unsafe fn ipi_startup(&mut self, core: ApicId, start_page: u8);

    /// Send a generic IPI.
    unsafe fn send_ipi(&mut self, icr: Icr);
}
