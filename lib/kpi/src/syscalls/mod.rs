// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! System call layer used by applications.
//!
//! Code in this module is not linked into the kernel.

mod io;
mod macros;
mod memory;
mod process;
mod system;

pub use crate::syscall;
pub use io::{Fs, Irq};
pub use memory::{PhysicalMemory, VSpace};
pub use process::Process;
pub use system::System;

/// Test that ensures we pass argument correctly (value, order), and receive
/// correct responses.
pub fn test_calls() {
    use crate::SystemCall;
    use core::ops::Range;

    const PRIMES: [u64; 6] = [5, 7, 11, 13, 17, 19];
    fn rs(range: Range<usize>) -> (u64, u64, u64) {
        let expected_r = PRIMES[range].iter().fold(1, |acc, x| acc * x);
        (0 /* Ok */, expected_r, expected_r + 1)
    }

    // We use a bunch of primes as arguments
    // Primes have the nice feature that multiplied, they give a unique number
    //
    // The kernel multiplies all arguments and returns it as `r1`
    // `r2` will be r1+1 etc.
    //
    // Except for nargs = 0, where we just return 0, 1, 2
    unsafe {
        // Don't test for syscall!(SystemCall::Test as u64, 1)
        let r1 = syscall!(SystemCall::Test as u64, 0xdeaf, 1);
        assert_ne!(r1, 0);

        let nargs = 0;
        let r1 = syscall!(SystemCall::Test as u64, nargs, 1);
        assert_eq!(r1, 0);
        let (r1, r2) = syscall!(SystemCall::Test as u64, nargs, 2);
        assert_eq!(r1, 0);
        assert_eq!(r2, 1);
        let (r1, r2, r3) = syscall!(SystemCall::Test as u64, nargs, 3);
        assert_eq!(r1, 0);
        assert_eq!(r2, 1);
        assert_eq!(r3, 2);

        let nargs = 1;
        let (expected_r1, expected_r2, expected_r3) = rs(0..nargs);
        let r1 = syscall!(SystemCall::Test as u64, nargs, PRIMES[0], 1);
        assert_eq!(r1, expected_r1);
        let (r1, r2) = syscall!(SystemCall::Test as u64, nargs, PRIMES[0], 2);
        assert_eq!(r1, expected_r1);
        assert_eq!(r2, expected_r2);
        let (r1, r2, r3) = syscall!(SystemCall::Test as u64, nargs, PRIMES[0], 3);
        assert_eq!(r1, expected_r1);
        assert_eq!(r2, expected_r2);
        assert_eq!(r3, expected_r3);

        let nargs = 2;
        let (expected_r1, expected_r2, expected_r3) = rs(0..nargs);
        let r1 = syscall!(SystemCall::Test as u64, nargs, PRIMES[0], PRIMES[1], 1);
        assert_eq!(r1, expected_r1);
        let (r1, r2) = syscall!(SystemCall::Test as u64, nargs, PRIMES[0], PRIMES[1], 2);
        assert_eq!(r1, expected_r1);
        assert_eq!(r2, expected_r2);
        let (r1, r2, r3) = syscall!(SystemCall::Test as u64, nargs, PRIMES[0], PRIMES[1], 3);
        assert_eq!(r1, expected_r1);
        assert_eq!(r2, expected_r2);
        assert_eq!(r3, expected_r3);

        let nargs = 3;
        let (expected_r1, expected_r2, _expected_r3) = rs(0..nargs);
        let r1 = syscall!(
            SystemCall::Test as u64,
            nargs,
            PRIMES[0],
            PRIMES[1],
            PRIMES[2],
            1
        );
        assert_eq!(r1, expected_r1);
        let (r1, r2) = syscall!(
            SystemCall::Test as u64,
            nargs,
            PRIMES[0],
            PRIMES[1],
            PRIMES[2],
            2
        );
        assert_eq!(r1, expected_r1);
        assert_eq!(r2, expected_r2);

        let nargs = 4;
        let (expected_r1, expected_r2, _expected_r3) = rs(0..nargs);
        let (r1, r2) = syscall!(
            SystemCall::Test as u64,
            nargs,
            PRIMES[0],
            PRIMES[1],
            PRIMES[2],
            PRIMES[3],
            2
        );
        assert_eq!(r1, expected_r1);
        assert_eq!(r2, expected_r2);
    }
}
