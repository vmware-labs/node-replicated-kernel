use x86::msr::{wrmsr, rdmsr, IA32_EFER, IA32_STAR, IA32_LSTAR, IA32_FMASK};
use x86::segmentation::{SegmentSelector};
use x86::rflags::{RFlags};

/// Enables syscall/sysret functionality.
pub fn enable_fast_syscalls(cs: SegmentSelector, cs_user: SegmentSelector) {

    unsafe {
        let mut star = rdmsr(IA32_STAR);
        star |= (cs.bits() as u64) << 32;
        star |= (cs_user.bits() as u64) << 48;

        wrmsr(IA32_STAR, star);
        log!("IA32_star: 0x{:x}", star);

        // System call RIP, currently 0
        wrmsr(IA32_LSTAR, 0);

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);

        wrmsr(IA32_FMASK, !RFlags::new().bits());
    }

    log!("Fast syscalls enabled!");
}