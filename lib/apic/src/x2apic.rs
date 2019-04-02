use driverkit::bitops::BitField;
use driverkit::{DriverControl, DriverState};
use log::{debug, trace};
use x86::msr::{
    rdmsr, wrmsr, IA32_APIC_BASE, IA32_TSC_DEADLINE, IA32_X2APIC_APICID, IA32_X2APIC_ESR,
    IA32_X2APIC_LVT_LINT0, IA32_X2APIC_LVT_TIMER, IA32_X2APIC_SELF_IPI, IA32_X2APIC_VERSION,
};

#[derive(Debug)]
pub struct X2APIC {
    state: DriverState,
    base: u64,
}

impl X2APIC {
    pub fn new() -> X2APIC {
        unsafe {
            X2APIC {
                state: DriverState::Uninitialized,
                base: rdmsr(IA32_APIC_BASE),
            }
        }
    }

    pub fn bsp(&self) -> bool {
        (self.base & (1 << 8)) > 0
    }

    /// Read local APIC ID.
    pub fn id(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
    }

    /// Read APIC version.
    pub fn version(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_VERSION) as u32 }
    }

    pub unsafe fn tsc_enable(&self) {
        // Enable TSC timer
        let mut lvt: u64 = rdmsr(IA32_X2APIC_LVT_TIMER);
        lvt |= 0 << 17;
        lvt |= 1 << 18;
        wrmsr(IA32_X2APIC_LVT_TIMER, lvt);
    }

    pub unsafe fn tsc_set(&self, value: u64) {
        wrmsr(IA32_TSC_DEADLINE, value);
    }

    pub unsafe fn send_self_ipi(&self, vector: u64) {
        wrmsr(IA32_X2APIC_SELF_IPI, vector);
    }
}

impl DriverControl for X2APIC {
    fn attach(&mut self) {
        self.set_state(DriverState::Attached(0));
        // Enable
        unsafe {
            self.base = rdmsr(IA32_APIC_BASE);
            self.base.set_bit(10, true); // Enable x2APIC
            self.base.set_bit(11, true); // Enable xAPIC
            wrmsr(IA32_APIC_BASE, self.base);

            let mut lint0 = rdmsr(IA32_X2APIC_LVT_LINT0);
            debug!("lint 0 is {:#b}", lint0);
            lint0 = 1 << 16 | (1 << 15) | (0b111 << 8) | 0x20;
            wrmsr(IA32_X2APIC_LVT_LINT0, lint0);

            let esr = rdmsr(IA32_X2APIC_ESR);
            debug!("esr is {:#b}", esr);
            trace!("Enabled x2APIC");
        }
    }

    fn detach(&mut self) {
        unsafe {
            self.base = rdmsr(IA32_APIC_BASE);
            self.base.set_bit(10, false); // x2APIC
            self.base.set_bit(11, false); // xAPIC
            wrmsr(IA32_APIC_BASE, self.base);
        }
        self.set_state(DriverState::Detached);
    }

    fn destroy(mut self) {
        self.detach();
        self.set_state(DriverState::Destroyed);
    }

    fn state(&self) -> DriverState {
        self.state
    }

    fn set_state(&mut self, st: DriverState) {
        self.state = st;
    }
}
