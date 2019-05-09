use core::intrinsics::{volatile_load, volatile_store};
use driverkit::bitops::BitField;
use driverkit::{DriverControl, DriverState};
use log::{info, trace};
use x86::msr::{rdmsr, wrmsr, IA32_APIC_BASE, IA32_TSC_DEADLINE};
use x86::xapic::*;

use super::*;

#[derive(Copy, Clone)]
#[allow(dead_code, non_camel_case_types)]
enum ApicRegister {
    XAPIC_ID = XAPIC_ID as isize,
    XAPIC_VERSION = XAPIC_VERSION as isize,
    XAPIC_TPR = XAPIC_TPR as isize,
    XAPIC_PPR = XAPIC_PPR as isize,
    XAPIC_EOI = XAPIC_EOI as isize,
    XAPIC_LDR = XAPIC_LDR as isize,
    XAPIC_SVR = XAPIC_SVR as isize,
    XAPIC_ISR0 = XAPIC_ISR0 as isize,
    XAPIC_ISR1 = XAPIC_ISR1 as isize,
    XAPIC_ISR2 = XAPIC_ISR2 as isize,
    XAPIC_ISR3 = XAPIC_ISR3 as isize,
    XAPIC_ISR4 = XAPIC_ISR4 as isize,
    XAPIC_ISR5 = XAPIC_ISR5 as isize,
    XAPIC_ISR6 = XAPIC_ISR6 as isize,
    XAPIC_ISR7 = XAPIC_ISR7 as isize,
    XAPIC_TMR0 = XAPIC_TMR0 as isize,
    XAPIC_TMR1 = XAPIC_TMR1 as isize,
    XAPIC_TMR2 = XAPIC_TMR2 as isize,
    XAPIC_TMR3 = XAPIC_TMR3 as isize,
    XAPIC_TMR4 = XAPIC_TMR4 as isize,
    XAPIC_TMR5 = XAPIC_TMR5 as isize,
    XAPIC_TMR6 = XAPIC_TMR6 as isize,
    XAPIC_TMR7 = XAPIC_TMR7 as isize,
    XAPIC_IRR0 = XAPIC_IRR0 as isize,
    XAPIC_IRR1 = XAPIC_IRR1 as isize,
    XAPIC_IRR2 = XAPIC_IRR2 as isize,
    XAPIC_IRR3 = XAPIC_IRR3 as isize,
    XAPIC_IRR4 = XAPIC_IRR4 as isize,
    XAPIC_IRR5 = XAPIC_IRR5 as isize,
    XAPIC_IRR6 = XAPIC_IRR6 as isize,
    XAPIC_IRR7 = XAPIC_IRR7 as isize,
    XAPIC_ESR = XAPIC_ESR as isize,
    XAPIC_LVT_CMCI = XAPIC_LVT_CMCI as isize,
    XAPIC_ICR0 = XAPIC_ICR0 as isize,
    XAPIC_ICR1 = XAPIC_ICR1 as isize,
    XAPIC_LVT_TIMER = XAPIC_LVT_TIMER as isize,
    XAPIC_LVT_THERMAL = XAPIC_LVT_THERMAL as isize,
    XAPIC_LVT_PMI = XAPIC_LVT_PMI as isize,
    XAPIC_LVT_LINT0 = XAPIC_LVT_LINT0 as isize,
    XAPIC_LVT_LINT1 = XAPIC_LVT_LINT1 as isize,
    XAPIC_LVT_ERROR = XAPIC_LVT_ERROR as isize,
    XAPIC_TIMER_INIT_COUNT = XAPIC_TIMER_INIT_COUNT as isize,
    XAPIC_TIMER_CURRENT_COUNT = XAPIC_TIMER_CURRENT_COUNT as isize,
    XAPIC_TIMER_DIV_CONF = XAPIC_TIMER_DIV_CONF as isize,
}

#[derive(Debug)]
pub struct XAPIC {
    state: DriverState,
    mmio_region: &'static mut [u32],
    base: u64,
}

impl XAPIC {
    fn read(&self, offset: ApicRegister) -> u32 {
        assert!(offset as usize % 4 == 0);
        let index = offset as usize / 4;
        unsafe { volatile_load(&self.mmio_region[index]) }
    }

    fn write(&mut self, offset: ApicRegister, val: u32) {
        assert!(offset as usize % 4 == 0);
        let index = offset as usize / 4;
        unsafe { volatile_store(&mut self.mmio_region[index], val) }
    }

    pub fn new(apic_region: &'static mut [u32]) -> XAPIC {
        unsafe {
            XAPIC {
                state: DriverState::Uninitialized,
                mmio_region: apic_region,
                base: rdmsr(IA32_APIC_BASE),
            }
        }
    }

    /// Is this the bootstrap core?
    pub fn bsp(&self) -> bool {
        (self.base & (1 << 8)) > 0
    }

    /// Read local APIC ID.
    pub fn id(&self) -> u32 {
        self.read(ApicRegister::XAPIC_ID)
    }

    /// Read APIC version.
    pub fn version(&self) -> u32 {
        self.read(ApicRegister::XAPIC_VERSION)
    }

    /// Enable TSC timer.
    pub unsafe fn tsc_enable(&mut self) {
        let mut lvt: u32 = self.read(ApicRegister::XAPIC_LVT_TIMER);
        lvt.set_bit(17, false);
        lvt.set_bit(18, true);
        self.write(ApicRegister::XAPIC_LVT_TIMER, lvt);
    }

    /// Set TSC deadline value.
    pub unsafe fn tsc_set(&self, value: u64) {
        wrmsr(IA32_TSC_DEADLINE, value);
    }

    pub unsafe fn ipi_init(&mut self) {
        let icr = Icr::new(
            0,
            1,
            DestinationShorthand::NoShorthand,
            DeliveryMode::Init,
            DestinationMode::Physical,
            DeliveryStatus::Idle,
            Level::Assert,
            TriggerMode::Level,
        );
        self.send_ipi(icr);
    }

    pub unsafe fn ipi_init_deassert(&mut self) {
        let icr = Icr::new(
            0,
            0,
            // INIT deassert is always sent to everyone, so we are supposed to specify:
            DestinationShorthand::AllIncludingSelf,
            DeliveryMode::Init,
            DestinationMode::Physical,
            DeliveryStatus::Idle,
            Level::Deassert,
            TriggerMode::Level,
        );
        self.send_ipi(icr);
    }

    pub unsafe fn ipi_startup(&mut self, start_page: u8) {
        info!("ipi_startup {}", start_page);
        let icr = Icr::new(
            start_page,
            1,
            DestinationShorthand::NoShorthand,
            DeliveryMode::StartUp,
            DestinationMode::Physical,
            DeliveryStatus::Idle,
            Level::Assert,
            TriggerMode::Edge,
        );
        self.send_ipi(icr);
    }

    unsafe fn send_ipi(&mut self, icr: Icr) {
        self.write(ApicRegister::XAPIC_ESR, 0);
        self.write(ApicRegister::XAPIC_ESR, 0);

        // 10.6 ISSUING INTERPROCESSOR INTERRUPTS
        info!("send ipi icr0 {:#b}", icr.lower());
        info!("send ipi icr1 {:#b}", icr.upper());
        self.write(ApicRegister::XAPIC_ICR1, icr.upper());
        self.write(ApicRegister::XAPIC_ICR0, icr.lower());

        loop {
            let icr = self.read(ApicRegister::XAPIC_ICR0);
            if (icr >> 12 & 0x1) == 0 {
                break;
            }
            if self.read(ApicRegister::XAPIC_ESR) > 0 {
                break;
            }
        }
        info!(
            "XAPIC ESR after send = {:?}",
            self.read(ApicRegister::XAPIC_ESR)
        );

        info!(
            "XAPIC ICR0 after send = {:#b}",
            self.read(ApicRegister::XAPIC_ICR0)
        );
    }
}

impl DriverControl for XAPIC {
    fn attach(&mut self) {
        self.set_state(DriverState::Attached(0));
        // Enable
        unsafe {
            self.base = rdmsr(IA32_APIC_BASE);
            self.base.set_bit(11, true); // Enable xAPIC
            wrmsr(IA32_APIC_BASE, self.base);
            trace!("Enabled xAPIC {:#b}", self.base);
        }
    }

    fn detach(&mut self) {
        unsafe {
            self.base = rdmsr(IA32_APIC_BASE);
            self.base.set_bit(11, false); // Disable xAPIC
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
