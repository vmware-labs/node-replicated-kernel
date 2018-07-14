use x86::bits64::rflags::RFlags;
use x86::msr::{rdmsr, wrmsr, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};
use x86::segmentation::SegmentSelector;
use x86::Ring;

extern "C" {
    #[no_mangle]
    fn syscall_enter();
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn syscall_handle() {
    slog!("got syscall");
    loop {}
}

/// Enables syscall/sysret functionality.
pub fn enable_fast_syscalls(_cs: SegmentSelector, _cs_user: SegmentSelector) {
    let cs_selector = SegmentSelector::new(1 as u16, Ring::Ring0) | SegmentSelector::TI_GDT;
    let ss_selector = SegmentSelector::new(2 as u16, Ring::Ring3) | SegmentSelector::TI_GDT;

    unsafe {
        let mut star = rdmsr(IA32_STAR);
        star |= (cs_selector.bits() as u64) << 32;
        star |= (ss_selector.bits() as u64) << 48;
        wrmsr(IA32_STAR, star);

        // System call RIP
        let rip = syscall_enter as usize as u64;
        wrmsr(IA32_LSTAR, rip);

        wrmsr(IA32_FMASK, !(RFlags::new().bits()));

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);
    }

    slog!("Fast syscalls enabled!");
}
