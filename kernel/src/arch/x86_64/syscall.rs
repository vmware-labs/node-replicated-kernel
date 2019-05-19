use x86::bits64::rflags::{self, RFlags};
use x86::msr::{rdmsr, wrmsr, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};
use x86::segmentation::SegmentSelector;
use x86::Ring;

extern "C" {
    #[no_mangle]
    fn syscall_enter();
}

use kpi::{SystemCall, SystemCallStatus};

use crate::prelude::NoDrop;
use core::mem;
use core::ops::Deref;

struct UserValue<T> {
    value: T,
}

impl<T> UserValue<T> {
    fn new(pointer: T) -> UserValue<T> {
        UserValue { value: pointer }
    }
}

impl<T> Deref for UserValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            rflags::stac();
            &self.value
        }
    }
}

impl<T> Drop for UserValue<T> {
    fn drop(&mut self) {
        unsafe { rflags::clac() };
    }
}

fn handle_print(buf: UserValue<&str>) -> SystemCallStatus {
    let buffer: &str = *buf;
    info!("handle_print: {:?}", buffer);
    SystemCallStatus::Ok
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn syscall_handle(
    function: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    unsafe {
        info!(
            "got syscall {} {} {} {} {} {}",
            function, arg1, arg2, arg3, arg4, arg5
        );
        let p = super::process::CURRENT_PROCESS.lock();
        info!("p {:?}", *p);
    }

    match SystemCall::new(function) {
        SystemCall::Print => {
            let buffer: *const u8 = arg1 as *const u8;
            let len: usize = arg2 as usize;
            let user_str = unsafe {
                let slice = core::slice::from_raw_parts(buffer, len);
                core::str::from_utf8_unchecked(slice)
            };
            handle_print(UserValue::new(user_str)) as u64
        }
        SystemCall::Exit => {
            info!("Process got exit, we are done for now...");
            super::debug::shutdown(crate::ExitReason::Ok)
        }
        _ => SystemCallStatus::NotSupported as u64,
    }
}

/// Enables syscall/sysret functionality.
pub fn enable_fast_syscalls(cs_selector: SegmentSelector, ss_selector: SegmentSelector) {
    unsafe {
        let mut star = rdmsr(IA32_STAR);
        star |= (cs_selector.bits() as u64) << 32;
        star |= (ss_selector.bits() as u64) << 48;
        wrmsr(IA32_STAR, star);

        // System call RIP
        let rip = syscall_enter as u64;
        wrmsr(IA32_LSTAR, rip);
        info!("syscalls jump to {:#x}", rip);

        wrmsr(IA32_FMASK, !(RFlags::new().bits()));

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);
    }

    debug!("Fast syscalls enabled!");
}
