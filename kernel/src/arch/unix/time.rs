use time::DateTime;

use libc;

pub mod tsc {
    use time::ONE_GHZ_IN_HZ;

    lazy_static! {
        /// TSC Frequency in Hz
        pub static ref TSC_FREQUENCY: u64 = {
            let cpuid = x86::cpuid::CpuId::new();
            return cpuid
                .get_tsc_info()
                .map_or(3*ONE_GHZ_IN_HZ, |tinfo| tinfo.tsc_frequency());
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

}

pub fn wallclock() -> DateTime {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let ltime: *mut libc::tm = libc::localtime(&t);

        DateTime {
            sec: (*ltime).tm_sec as u8,
            min: (*ltime).tm_min as u8,
            day: (*ltime).tm_mday as u8,
            hour: (*ltime).tm_hour as u8,
            mon: ((*ltime).tm_mon + 1) as u8,
            year: ((*ltime).tm_year + 1900) as u64,
        }
    }
}

pub fn precise_time_ns() -> u64 {
    tsc::precise_time_ns()
}
