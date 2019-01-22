use core::fmt;
use core::ops;
pub use core::time::Duration;
pub use x86::cpuid;

use arch::time::{precise_time_ns, wallclock};

pub const ONE_GHZ_IN_HZ: u64 = 1_000_000_000;

lazy_static! {
    pub static ref WALL_TIME_ANCHOR: DateTime = wallclock();
    pub static ref BOOT_TIME_ANCHOR: Instant = Instant::now();
}

#[inline]
pub fn duration_since_boot() -> Duration {
    (*BOOT_TIME_ANCHOR).elapsed()
}

#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DateTime {
    pub sec: u8,
    pub min: u8,
    pub hour: u8,
    pub day: u8,
    pub mon: u8,
    pub year: u64,
}

impl DateTime {
    const FEBRUARY: u64 = 2;
    const POSIX_BASE_YEAR: u64 = 1970;
    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_DAY: u64 = 86400;
    const DAYS_PER_COMMON_YEAR: u64 = 365;
    const DAYS_PER_LEAP_YEAR: u64 = 366;

    fn month_to_days(month: u64) -> u64 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => !0,
        }
    }

    fn is_leap_year(year: u64) -> bool {
        ((year % 4) == 0 && (year % 100) != 0) || (year % 400) == 0
    }

    fn year_to_days(year: u64) -> u64 {
        if DateTime::is_leap_year(year) {
            DateTime::DAYS_PER_LEAP_YEAR
        } else {
            DateTime::DAYS_PER_COMMON_YEAR
        }
    }

    /// The number of seconds elapsed since Thursday, 1 January 1970, 00:00 UTC
    pub fn as_unix_time(&self) -> u64 {
        let year: u64 = self.year as u64;
        if year < DateTime::POSIX_BASE_YEAR {
            return 0;
        }

        // Years to days
        let mon: u64 = self.mon as u64;
        let mut days = if DateTime::is_leap_year(year) && mon > DateTime::FEBRUARY {
            1
        } else {
            0
        };

        for i in DateTime::POSIX_BASE_YEAR..year {
            days += DateTime::year_to_days(i);
        }

        // Month to days
        for i in 1..self.mon {
            days += DateTime::month_to_days(i as u64);
        }

        // Add days in current month
        days += self.day as u64 - 1;

        // To seconds
        (days * DateTime::SECS_PER_DAY)
            + (self.hour as u64 * DateTime::SECS_PER_HOUR)
            + (self.min as u64 * DateTime::SECS_PER_MINUTE)
            + self.sec as u64
    }
}

impl fmt::Debug for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DateTime {}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            self.year, self.mon, self.day, self.hour, self.min, self.sec
        )
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            self.year, self.mon, self.day, self.hour, self.min, self.sec
        )
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u128);

impl Instant {
    pub fn now() -> Instant {
        Instant(precise_time_ns() as u128)
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        if earlier > *self {
            panic!("Second instance is later than self");
        } else {
            Duration::from_nanos((self.0 - earlier.0) as u64)
        }
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now() - *self
    }
}

impl ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        Instant(self.0 + other.as_nanos())
    }
}

impl ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, other: Duration) {
        *self = *self + other;
    }
}

impl ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Instant {
        Instant(self.0 - other.as_nanos())
    }
}

impl ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}

impl ops::SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Instant({})", self.0)
    }
}
