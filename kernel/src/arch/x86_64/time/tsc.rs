use arch::time::rtc;
use time::ONE_GHZ_IN_HZ;

lazy_static! {
    /// TSC Frequency in Hz
    pub static ref TSC_FREQUENCY: u64 = {
        let cpuid = x86::cpuid::CpuId::new();
        let has_tsc = cpuid
            .get_feature_info()
            .map_or(false, |finfo| finfo.has_tsc());
        assert!(has_tsc);
        let _has_invariant_tsc = cpuid
            .get_extended_function_info()
            .map_or(false, |efinfo| efinfo.has_invariant_tsc());

        if cpuid.get_tsc_info().is_some() {
            return cpuid
                .get_tsc_info()
                .map_or(3*ONE_GHZ_IN_HZ, |tinfo| tinfo.tsc_frequency());
        } else if cpuid.get_hypervisor_info().is_some() {
            let hv = cpuid.get_hypervisor_info().unwrap();
            return hv.tsc_frequency()
                .map_or(3*ONE_GHZ_IN_HZ, |tsc_khz| tsc_khz as u64 * 1000);
        } else if cpuid.get_processor_frequency_info().is_some() {
            return cpuid
                .get_processor_frequency_info()
                .map_or(3*ONE_GHZ_IN_HZ, |pinfo| pinfo.processor_max_frequency() as u64 * 1000000);
        } else {
            unsafe {
                debug!("{:?}", x86::cpuid::cpuid!(0x15, 0x0));
                let rtc = rtc::now();
                while rtc::now().as_unix_time() < (rtc.as_unix_time() + 1) {
                    core::arch::x86_64::_mm_pause();
                }

                let rtc = rtc::now();
                let start = x86::time::rdtsc();
                while rtc::now().as_unix_time() < (rtc.as_unix_time() + 1) {
                    core::arch::x86_64::_mm_pause();
                }
                let cycles_per_sec = x86::time::rdtsc() - start;
                info!("Estimated TSC rate is {} cycles per second.", cycles_per_sec);
                cycles_per_sec
            }
        }
    };
}

#[inline]
fn tsc_to_ns(hz: u64) -> u64 {
    (hz as f64 / (*TSC_FREQUENCY as f64 / ONE_GHZ_IN_HZ as f64)) as u64
}

#[inline]
pub fn precise_time_ns() -> u64 {
    unsafe { tsc_to_ns(x86::time::rdtsc()) as u64 }
}
