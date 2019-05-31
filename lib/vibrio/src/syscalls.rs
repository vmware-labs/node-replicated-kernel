//! The system call interface to the bespin kernel.
//!
//! The function naming convention syscall_$x_$y where
//! $x is the number of input arguments and $y is the
//! number of return arguments we expect.
//!
//! For the syscall! macro we pass the syscall arguments first
//! and the last argument specifies how many return values we
//! expect.
//!
//! # Note
//! The definitions which are shared between the kernel
//! and user-space reside in a different [`kpi`] (kernel
//! public interface) crate.
use kpi::*;

use log::info;
use x86::bits64::paging::{PAddr, VAddr};

macro_rules! syscall {
    ($arg0:expr, 1) => {
        crate::syscalls::syscall_1_1($arg0 as u64)
    };

    ($arg0:expr, $arg1:expr, 1) => {
        crate::syscalls::syscall_2_1($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, 1) => {
        crate::syscalls::syscall_3_1($arg0 as u64, $arg1 as u64, $arg2 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, 1) => {
        crate::syscalls::syscall_4_1($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, 2) => {
        crate::syscalls::syscall_4_2($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, 3) => {
        crate::syscalls::syscall_4_3($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, 1) => {
        crate::syscalls::syscall_5_1(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
        )
    };
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_1_1(arg0: u64) -> u64 {
    let mut ret1: u64;
    asm!("syscall" : "={rax}" (ret1) : "{rdi}" (arg0) : "rcx", "r11", "memory" : "volatile");
    ret1
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_1_2(arg0: u64) -> (u64, u64) {
    let mut ret1: u64;
    let mut ret2: u64;
    asm!("syscall" : "={rax}" (ret1), "={r}" (ret2) : "{rdi}" (arg0) : "rcx", "r11", "memory" : "volatile");
    (ret1, ret2)
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_2_1(arg1: u64, arg2: u64) -> u64 {
    let mut ret1: u64;
    asm!("syscall" : "={rax}" (ret1) : "{rdi}" (arg1), "{rsi}" (arg2)
                   : "rcx", "r11", "memory" : "volatile");
    ret1
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_3_1(arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let mut ret: u64;
    asm!("syscall" : "={rax}" (ret) : "{rdi}" (arg1), "{rsi}" (arg2), "{rdx}" (arg3)
                   : "rcx", "r11", "memory" : "volatile");
    ret
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_4_1(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let mut ret: u64;
    asm!("syscall" : "={rax}" (ret)
                   : "{rdi}"  (arg1), "{rsi}"  (arg2), "{rdx}"  (arg3), "{r10}"  (arg4)
                   : "rcx", "r11", "memory" : "volatile");
    ret
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_4_2(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> (u64, u64) {
    let mut ret: u64;
    let mut ret2: u64;
    asm!("syscall" : "={rax}" (ret) "={rdi}" (ret2)
                   : "{rdi}"  (arg1), "{rsi}"  (arg2), "{rdx}"  (arg3), "{r10}"  (arg4)
                   : "rcx", "r11", "memory" : "volatile");
    (ret, ret2)
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_4_3(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> (u64, u64, u64) {
    let ret: u64;
    let ret2: u64;
    let ret3: u64;
    asm!("syscall" : "={rax}" (ret) "={rdi}" (ret2) "={rsi}" (ret3)
                   : "{rdi}"  (arg1), "{rsi}"  (arg2), "{rdx}"  (arg3), "{r10}"  (arg4)
                   : "rcx", "r11", "memory" : "volatile");
    (ret, ret2, ret3)
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall_5_1(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let mut ret: u64;
    asm!("syscall" : "={rax}" (ret)
                   : "{rdi}" (arg1), "{rsi}" (arg2), "{rdx}" (arg3), "{r10}" (arg4), "{r8}" (arg5)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
#[allow(unused_mut)]
unsafe fn syscall6_1(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    let mut ret: u64;
    asm!("syscall" : "={rax}" (ret)
                   : "{rax}" (arg0), "{rdi}" (arg1), "{rsi}" (arg2), "{rdx}" (arg3),
                     "{r10}" (arg4), "{r8}" (arg5), "{r9}" (arg6)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

/// Print `buffer` on the console.
pub fn print(buffer: &str) -> Result<(), SystemCallError> {
    let r = unsafe {
        syscall!(
            SystemCall::Process as u64,
            ProcessOperation::Log as u64,
            buffer.as_ptr() as u64,
            buffer.len(),
            1
        )
    };

    if r == 0 {
        Ok(())
    } else {
        Err(SystemCallError::from(r))
    }
}

/// Exit the process (pass an error `code` to exit).
pub fn exit(code: u64) -> ! {
    unsafe {
        syscall!(
            SystemCall::Process as u64,
            ProcessOperation::Exit as u64,
            code,
            1
        );

        // This stops the process and never returns:
        unreachable!()
    }
}

/// Manipulate the virtual address space.
pub unsafe fn vspace(
    op: VSpaceOperation,
    base: u64,
    bound: u64,
) -> Result<(VAddr, PAddr), SystemCallError> {
    let (err, paddr, size) = syscall!(SystemCall::VSpace as u64, op as u64, base, bound, 3);
    if err == 0 {
        //info!("bound {:#x} size {:#x}", bound, size);
        debug_assert!(bound == size);
        Ok((VAddr::from(base), PAddr::from(paddr)))
    } else {
        Err(SystemCallError::from(err))
    }
}
