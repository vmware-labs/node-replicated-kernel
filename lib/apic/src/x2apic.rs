// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::trace;

use driverkit::{DriverControl, DriverState};
use x86::apic::x2apic::X2APIC;
use x86::apic::{ApicControl, ApicId, Icr};

/// An x2APIC driver
#[derive(Debug)]
pub struct X2APICDriver {
    timer_vector: u8,
    state: DriverState,
    inner: X2APIC,
}

impl Default for X2APICDriver {
    /// Create a new x2APIC driver object.
    fn default() -> Self {
        Self {
            timer_vector: crate::TSC_TIMER_VECTOR,
            state: DriverState::Uninitialized,
            inner: X2APIC::new(),
        }
    }
}

impl X2APICDriver {
    pub const fn new() -> Self {
        Self {
            timer_vector: crate::TSC_TIMER_VECTOR,
            state: DriverState::Uninitialized,
            inner: X2APIC::new(),
        }
    }
}

impl crate::ApicDriver for X2APICDriver {
    /// Is a bootstrap processor?
    fn bsp(&self) -> bool {
        self.inner.bsp()
    }

    /// Return APIC ID.
    fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Return the logical APIC ID.
    fn logical_id(&self) -> u32 {
        self.inner.logical_id()
    }

    /// Read APIC version
    fn version(&self) -> u32 {
        self.inner.version()
    }

    /// End Of Interrupt -- Acknowledge interrupt delivery.
    fn eoi(&mut self) {
        self.inner.eoi()
    }

    /// Enable TSC deadline timer.
    fn tsc_enable(&mut self) {
        self.inner.tsc_enable(self.timer_vector)
    }

    /// Set TSC deadline value.
    fn tsc_set(&self, value: u64) {
        self.inner.tsc_set(value)
    }

    /// Send a INIT IPI to a core.
    unsafe fn ipi_init(&mut self, core: ApicId) {
        self.inner.ipi_init(core)
    }

    /// Deassert INIT IPI.
    unsafe fn ipi_init_deassert(&mut self) {
        self.inner.ipi_init_deassert()
    }

    /// Send a STARTUP IPI to a core.
    unsafe fn ipi_startup(&mut self, core: ApicId, start_page: u8) {
        self.inner.ipi_startup(core, start_page)
    }

    /// Send a generic IPI.
    unsafe fn send_ipi(&mut self, icr: Icr) {
        trace!("sending icr {:?}", icr);
        self.inner.send_ipi(icr)
    }
}

impl DriverControl for X2APICDriver {
    /// Attach to the device
    fn attach(&mut self) {
        self.set_state(DriverState::Attached(0));
        self.inner.attach();
    }

    /// Detach from the device
    fn detach(&mut self) {
        self.inner.detach();
        self.set_state(DriverState::Detached);
    }

    /// Destroy the device.
    fn destroy(mut self) {
        self.detach();
        self.set_state(DriverState::Destroyed);
    }

    /// Query driver state
    fn state(&self) -> DriverState {
        self.state
    }

    /// Set the state of the driver
    fn set_state(&mut self, st: DriverState) {
        self.state = st;
    }
}
