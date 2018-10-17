use x86::time;

use core::fmt;
use core::ops;

pub use core::time::Duration;
pub use x86::cpuid;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u128);

const ONE_GHZ_IN_HZ: u64 = 1_000_000_000;

lazy_static! {
    /// TSC Frequency in Hz
    pub static ref TSC_FREQUENCY: u64 = {
        let cpuid = x86::cpuid::CpuId::new();
        let has_tsc = cpuid
            .get_feature_info()
            .map_or(false, |finfo| finfo.has_tsc());
        let has_invariant_tsc = cpuid
            .get_extended_function_info()
            .map_or(false, |efinfo| efinfo.has_invariant_tsc());
        assert!(has_tsc && has_invariant_tsc);
        let hypervisor_base = raw_cpuid::cpuid!(0x40000000, 0);
        let is_kvm = hypervisor_base.eax >= 0x40000010
            && hypervisor_base.ebx == 0x4b4d564b
            && hypervisor_base.ecx == 0x564b4d56
            && hypervisor_base.edx == 0x4d;

        if cpuid.get_tsc_info().is_some() {
            debug!("TSC Info found");
            // Nominal TSC frequency = ( CPUID.15H.ECX[31:0] * CPUID.15H.EBX[31:0] ) ÷ CPUID.15H.EAX[31:0]
            panic!("TODO -- update x86 lib");
            /*return cpuid
                .get_tsc_info()
                .map_or(1, |tinfo| tinfo.tsc_frequency());*/
        } else if cpuid.get_processor_frequency_info().is_some() {
            debug!("Processor frequency found");
            return cpuid
                .get_processor_frequency_info()
                .map_or(2, |pinfo| pinfo.processor_max_frequency() as u64 * 1000000);
        } else if is_kvm {
            debug!("Is KVM");
            // vm aware tsc frequency retrieval: https://lwn.net/Articles/301888/
            // # EAX: (Virtual) TSC frequency in kHz.
            // # EBX: (Virtual) Bus (local apic timer) frequency in kHz.
            // # ECX, EDX: RESERVED (Per above, reserved fields are set to zero).
            let virt_tinfo = raw_cpuid::cpuid!(0x40000010, 0);
            return virt_tinfo.eax as u64 * 1000;
        } else {
            warn!("Can't determine TSC frequency, we assume 2 GHz. All timing information is inaccurate.");
            return 2*ONE_GHZ_IN_HZ;
        }
    };
}

fn hz_to_ns(hz: u128) -> u128 {
    // TODO: proper floating point division?
    hz / (((*TSC_FREQUENCY / ONE_GHZ_IN_HZ) as u128) * 10) / 10
}

impl Instant {
    pub fn now() -> Instant {
        unsafe { Instant(hz_to_ns(time::rdtsc() as u128)) }
    }
}

impl ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        Instant(self.0 + other.as_nanos())
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Instant({})", self.0)
    }
}
