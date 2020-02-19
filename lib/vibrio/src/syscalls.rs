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
//! # Notes
//! The definitions which are shared between the kernel
//! and user-space reside in a different [`kpi`] (kernel
//! public interface) crate.
//!
//! We follow the System V register conventions which
//! uses `%rdi` as it's first argument. This is different
//! from Linux which tries to squeeze in one more syscall
//! argument by adding `%rax` to the mix.

#![allow(unused)]

pub use kpi::arch::{SaveArea, VirtualCpu};
pub use kpi::*;

use x86::bits64::paging::{PAddr, VAddr};

macro_rules! syscall {
    ($arg0:expr, 1) => {
        crate::syscalls::syscall_1_1($arg0 as u64)
    };

    ($arg0:expr, $arg1:expr, 1) => {
        crate::syscalls::syscall_2_1($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, 2) => {
        crate::syscalls::syscall_2_2($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, 3) => {
        crate::syscalls::syscall_2_3($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, 1) => {
        crate::syscalls::syscall_3_1($arg0 as u64, $arg1 as u64, $arg2 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, 2) => {
        crate::syscalls::syscall_3_2($arg0 as u64, $arg1 as u64, $arg2 as u64)
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
unsafe fn syscall_1_1(arg0: u64) -> u64 {
    let ret1: u64;
    asm!("syscall" : "={rax}" (ret1) : "{rdi}" (arg0) : "rcx", "r11", "memory" : "volatile");
    ret1
}

#[inline(always)]
unsafe fn syscall_1_2(arg0: u64) -> (u64, u64) {
    let ret1: u64;
    let ret2: u64;
    asm!("syscall" : "={rax}" (ret1), "={r}" (ret2) : "{rdi}" (arg0) : "rcx", "r11", "memory" : "volatile");
    (ret1, ret2)
}

#[inline(always)]
unsafe fn syscall_2_1(arg1: u64, arg2: u64) -> u64 {
    let ret1: u64;
    asm!("syscall" : "={rax}" (ret1) : "{rdi}" (arg1), "{rsi}" (arg2)
                   : "rcx", "r11", "memory" : "volatile");
    ret1
}

#[inline(always)]
unsafe fn syscall_2_2(arg1: u64, arg2: u64) -> (u64, u64) {
    let ret1: u64;
    let ret2: u64;
    asm!("syscall" : "={rax}" (ret1) "={rdi}" (ret2) : "{rdi}" (arg1), "{rsi}" (arg2)
                   : "rcx", "r11", "memory" : "volatile");
    (ret1, ret2)
}

#[inline(always)]
unsafe fn syscall_2_3(arg1: u64, arg2: u64) -> (u64, u64, u64) {
    let ret1: u64;
    let ret2: u64;
    let ret3: u64;

    asm!("syscall" : "={rax}" (ret1) "={rdi}" (ret2) "={rsi}" (ret3)
                   : "{rdi}" (arg1), "{rsi}" (arg2)
                   : "rcx", "r11", "memory" : "volatile");
    (ret1, ret2, ret3)
}

#[inline(always)]
unsafe fn syscall_3_1(arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    asm!("syscall" : "={rax}" (ret) : "{rdi}" (arg1), "{rsi}" (arg2), "{rdx}" (arg3)
                   : "rcx", "r11", "memory" : "volatile");
    ret
}

#[inline(always)]
unsafe fn syscall_3_2(arg1: u64, arg2: u64, arg3: u64) -> (u64, u64) {
    let ret1: u64;
    let ret2: u64;
    asm!("syscall" : "={rax}" (ret1) "={rdi}" (ret2)
                   : "{rdi}" (arg1), "{rsi}" (arg2), "{rdx}" (arg3)
                   : "rcx", "r11", "memory" : "volatile");
    (ret1, ret2)
}

#[inline(always)]
unsafe fn syscall_4_1(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    asm!("syscall" : "={rax}" (ret)
                   : "{rdi}"  (arg1), "{rsi}"  (arg2), "{rdx}"  (arg3), "{r10}"  (arg4)
                   : "rcx", "r11", "memory" : "volatile");
    ret
}

#[inline(always)]
unsafe fn syscall_4_2(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> (u64, u64) {
    let ret: u64;
    let ret2: u64;
    asm!("syscall" : "={rax}" (ret) "={rdi}" (ret2)
                   : "{rdi}"  (arg1), "{rsi}"  (arg2), "{rdx}"  (arg3), "{r10}"  (arg4)
                   : "rcx", "r11", "memory" : "volatile");
    (ret, ret2)
}

#[inline(always)]
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
unsafe fn syscall_5_1(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;
    asm!("syscall" : "={rax}" (ret)
                   : "{rdi}" (arg1), "{rsi}" (arg2), "{rdx}" (arg3), "{r10}" (arg4), "{r8}" (arg5)
                   : "rcx", "r11", "memory"
                   : "volatile");
    ret
}

#[inline(always)]
unsafe fn syscall6_1(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    let ret: u64;
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

/// Sets the VCPU memory location for the upcall mechanism.
///
/// This is allocated and controlled by the kernel, it doesn't move and
/// should live as long as the current CPU is allocated to the process.
pub fn vcpu_control_area() -> Result<&'static mut VirtualCpu, SystemCallError> {
    let (r, control) = unsafe {
        syscall!(
            SystemCall::Process as u64,
            ProcessOperation::GetVCpuArea as u64,
            2
        )
    };

    if r == 0 {
        let vaddr = VAddr::from(control);
        assert!(vaddr.is_base_page_aligned());
        let vcpu_ctl: *mut VirtualCpu = vaddr.as_mut_ptr::<VirtualCpu>();
        unsafe { Ok(&mut *vcpu_ctl) }
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
        debug_assert_eq!(
            bound, size,
            "VSpace Map should return mapped region size as 2nd argument"
        );
        Ok((VAddr::from(base), PAddr::from(paddr)))
    } else {
        Err(SystemCallError::from(err))
    }
}

/// Manipulate the CPU interrupt alloction table.
pub fn irqalloc(vec: u64, core: u64) -> Result<(), SystemCallError> {
    let (r, retvec, retcore) = unsafe {
        syscall!(
            SystemCall::Process as u64,
            ProcessOperation::AllocateVector as u64,
            vec,
            core,
            3
        )
    };

    assert_eq!(vec, retvec);
    assert_eq!(core, retcore);

    if r == 0 {
        Ok(())
    } else {
        Err(SystemCallError::from(r))
    }
}

pub unsafe fn file_create(
    op: FileOperation,
    pathname: &str,
    modes: u64,
) -> Result<u64, SystemCallError> {
    let (r, fd) = unsafe {
        syscall_4_2(
            SystemCall::FileIO as u64,
            op as u64,
            pathname.as_ptr() as u64,
            modes,
        )
    };

    if r == 0 {
        Ok(fd)
    } else {
        Err(SystemCallError::from(r))
    }
}

pub fn file_close(op: FileOperation, fd: u64) -> Result<u64, SystemCallError> {
    let r = unsafe { syscall_3_1(SystemCall::FileIO as u64, op as u64, fd) };

    if r == 0 {
        Ok(r)
    } else {
        Err(SystemCallError::from(r))
    }
}
