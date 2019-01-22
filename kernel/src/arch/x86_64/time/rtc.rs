use x86::io::{inb, outb};

use time::DateTime;

const RTC_COMMAND: u16 = 0x70;
const RTC_DATA: u16 = 0x71;
const RTC_NMI_DISABLE: u8 = 1 << 7;
const RTC_SEC: u8 = 0x00;
const RTC_MIN: u8 = 0x02;
const RTC_HOUR: u8 = 0x04;
const RTC_DAY: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_STATUS_A: u8 = 0x0a;
const RTC_UIP: u8 = (1 << 7);

fn bcd_to_bin(bcd: u8) -> u8 {
    ((bcd >> 4) & 0x0f) * 10 + (bcd & 0x0f)
}

unsafe fn rtc_read(reg: u8) -> u8 {
    outb(RTC_COMMAND, reg | RTC_NMI_DISABLE);
    return inb(RTC_DATA);
}

pub unsafe fn now() -> DateTime {
    while rtc_read(RTC_STATUS_A) & RTC_UIP > 0 {
        core::arch::x86_64::_mm_pause();
    }

    let dt = DateTime {
        sec: bcd_to_bin(rtc_read(RTC_SEC)),
        min: bcd_to_bin(rtc_read(RTC_MIN)),
        hour: bcd_to_bin(rtc_read(RTC_HOUR)),
        day: bcd_to_bin(rtc_read(RTC_DAY)),
        mon: bcd_to_bin(rtc_read(RTC_MONTH)),
        year: bcd_to_bin(rtc_read(RTC_YEAR)) as u64 + 2000,
    };

    assert!(dt.sec <= 60);
    assert!(dt.min <= 60);
    assert!(dt.hour <= 24);
    assert!(dt.day <= 31);
    assert!(dt.mon >= 1 && dt.mon <= 12);

    dt
}
