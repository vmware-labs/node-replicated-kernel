use x86::msr::{wrmsr, rdmsr, IA32_EFER, IA32_STAR, IA32_LSTAR, IA32_FMASK};
use x86::segmentation::*;
use x86::rflags::{RFlags};

/// Enables syscall/sysret functionality.
pub fn enable_fast_syscalls(cs: SegmentSelector, cs_user: SegmentSelector) {

    let cs_selector = SegmentSelector::new(1 as u16) | RPL_0 | TI_GDT;
    let ss_selector = SegmentSelector::new(2 as u16) | RPL_3 | TI_GDT;

    unsafe {
        let mut star = rdmsr(IA32_STAR);
        star |= (cs_selector.bits() as u64) << 32;
        star |= (ss_selector.bits() as u64) << 48;

        wrmsr(IA32_STAR, star);
        log!("IA32_star: 0x{:x}", star);

        // System call RIP, currently 0
        wrmsr(IA32_LSTAR, 0);

        wrmsr(IA32_FMASK, !(RFlags::new().bits()) );

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);
    }

    log!("Fast syscalls enabled!");
}