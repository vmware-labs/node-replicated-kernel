use core::mem::{transmute};
use ::mm::{paddr_to_kernel_vaddr};

use x86::msr::{wrmsr, rdmsr, IA32_EFER, IA32_STAR, IA32_LSTAR, IA32_FMASK};
use x86::segmentation::*;
use x86::rflags::{RFlags};

extern "C" {
    #[no_mangle]
    fn syscall_enter();
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn syscall_handle() {
    log!("got syscall");
    loop {}
}

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
        let rip = syscall_enter as usize as u64;
        log!("set rip to {:x}", rip);
        wrmsr(IA32_LSTAR, rip);

        wrmsr(IA32_FMASK, !(RFlags::new().bits()) );

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);
    }

    log!("Fast syscalls enabled!");
}