// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The system call interface to the nrk kernel.
//!
//! The function naming convention syscall_$x_$y where
//! $x is the number of input arguments and $y is the
//! number of return arguments we expect.
//!
//! For the syscall! macro we pass the syscall arguments first
//! and the last argument specifies how many return values we
//! expect.
//!
//! We follow the System V register conventions which
//! uses `%rdi` as it's first argument. This is different
//! from Linux which tries to squeeze in one more syscall
//! argument by adding `%rax` to the mix.
#![allow(unused)]

use core::arch::asm;

// If you modify this macro, make sure to also update `super::test_calls` function to invoke
// the new combinations!
#[macro_export]
macro_rules! syscall {
    ($arg0:expr, 1) => {
        crate::arch::syscalls::syscall_1_1($arg0 as u64)
    };

    ($arg0:expr, $arg1:expr, 1) => {
        crate::arch::syscalls::syscall_2_1($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, 2) => {
        crate::arch::syscalls::syscall_2_2($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, 3) => {
        crate::arch::syscalls::syscall_2_3($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, 1) => {
        crate::arch::syscalls::syscall_3_1($arg0 as u64, $arg1 as u64, $arg2 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, 2) => {
        crate::arch::syscalls::syscall_3_2($arg0 as u64, $arg1 as u64, $arg2 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, 3) => {
        crate::arch::syscalls::syscall_3_3($arg0 as u64, $arg1 as u64, $arg2 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, 1) => {
        crate::arch::syscalls::syscall_4_1($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, 2) => {
        crate::arch::syscalls::syscall_4_2($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, 3) => {
        crate::arch::syscalls::syscall_4_3($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, 1) => {
        crate::arch::syscalls::syscall_5_1(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
        )
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, 2) => {
        crate::arch::syscalls::syscall_5_2(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
        )
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, 1) => {
        crate::arch::syscalls::syscall_6_1(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
            $arg5 as u64,
        )
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, 2) => {
        crate::arch::syscalls::syscall_6_2(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
            $arg5 as u64,
        )
    };
}

// Note: the functions below are `pub(crate)` but should NOT be invoked directly.
// Instead use the `syscall!` macro above.

#[inline(always)]
pub(crate) unsafe fn syscall_1_1(arg0: u64) -> u64 {
    let ret1: u64;
    asm!(
        "svc 0",
        in("x0") arg0,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
    );

    ret1
}

#[inline(always)]
pub(crate) unsafe fn syscall_1_2(arg0: u64) -> (u64, u64) {
    let ret1: u64;
    let ret2: u64;

    asm!(
        "svc 0",
        in("x0") arg0,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
        lateout("x1") ret2,
    );

    (ret1, ret2)
}

#[inline(always)]
pub(crate) unsafe fn syscall_2_1(arg1: u64, arg2: u64) -> u64 {
    let ret1: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
    );

    ret1
}

#[inline(always)]
pub(crate) unsafe fn syscall_2_2(arg1: u64, arg2: u64) -> (u64, u64) {
    let ret1: u64;
    let ret2: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
        lateout("x1") ret2,
    );

    (ret1, ret2)
}

#[inline(always)]
pub(crate) unsafe fn syscall_2_3(arg1: u64, arg2: u64) -> (u64, u64, u64) {
    let ret1: u64;
    let ret2: u64;
    let ret3: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
        lateout("x1") ret2,
        lateout("x2") ret3,
    );

    (ret1, ret2, ret3)
}

#[inline(always)]
pub(crate) unsafe fn syscall_3_1(arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
    );

    ret
}

#[inline(always)]
pub(crate) unsafe fn syscall_3_2(arg1: u64, arg2: u64, arg3: u64) -> (u64, u64) {
    let ret1: u64;
    let ret2: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
        lateout("x1") ret2,
    );

    (ret1, ret2)
}

#[inline(always)]
pub(crate) unsafe fn syscall_3_3(arg1: u64, arg2: u64, arg3: u64) -> (u64, u64, u64) {
    let ret1: u64;
    let ret2: u64;
    let ret3: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret1,
        lateout("x1") ret2,
        lateout("x2") ret3,
    );

    (ret1, ret2, ret3)
}

#[inline(always)]
pub(crate) unsafe fn syscall_4_1(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
    );

    ret
}

#[inline(always)]
pub(crate) unsafe fn syscall_4_2(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> (u64, u64) {
    let ret: u64;
    let ret2: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
        lateout("x1") ret2,
    );

    (ret, ret2)
}

#[inline(always)]
pub(crate) unsafe fn syscall_4_3(arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> (u64, u64, u64) {
    let ret: u64;
    let ret2: u64;
    let ret3: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
        lateout("x1") ret2,
        lateout("x2") ret3,
    );

    (ret, ret2, ret3)
}

#[inline(always)]
pub(crate) unsafe fn syscall_5_1(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        in("x4") arg5,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
    );

    ret
}

#[inline(always)]
pub(crate) unsafe fn syscall_5_2(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> (u64, u64) {
    let ret: u64;
    let ret2: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        in("x4") arg5,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
        lateout("x1") ret2,
    );

    (ret, ret2)
}

#[inline(always)]
pub(crate) unsafe fn syscall_6_1(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    let ret: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        in("x4") arg5,
        in("x5") arg6,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
    );

    ret
}

#[inline(always)]
pub(crate) unsafe fn syscall_6_2(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> (u64, u64) {
    let ret: u64;
    let ret2: u64;

    asm!(
        "svc 0",
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        in("x3") arg4,
        in("x4") arg5,
        in("x5") arg6,
        out("x6") _, // clobbered by syscall
        out("x7") _, // clobbered by syscall
        lateout("x0") ret,
        lateout("x1") ret2,
    );

    (ret, ret2)
}
