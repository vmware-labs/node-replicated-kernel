use x86::apic::xapic::XAPIC;
use x86::apic::{ApicControl, ApicId, Icr};

use driverkit::{DriverControl, DriverState};

use log::info;

/// A device driver for an XAPIC.
#[derive(Debug)]
pub struct XAPICDriver {
    inner: XAPIC,
    state: DriverState,
}

impl XAPICDriver {
    /// Create a new driver object.
    pub fn new(mmio_region: &'static mut [u32]) -> XAPICDriver {
        XAPICDriver {
            inner: XAPIC::new(mmio_region),
            state: DriverState::Uninitialized,
        }
    }
}

impl ApicControl for XAPICDriver {
    /// Is a bootstrap processor?
    fn bsp(&self) -> bool {
        self.inner.bsp()
    }

    /// Return APIC ID.
    fn id(&self) -> u32 {
        self.inner.id()
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
        self.inner.tsc_enable()
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
        self.inner.send_ipi(icr)
    }
}

impl DriverControl for XAPICDriver {
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
