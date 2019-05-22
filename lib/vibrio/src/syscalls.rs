//! The system call interface to the bespin kernel.
//!
//! # Note
//! The definitions which are shared between the kernel
//! and user-space reside in a different [`kpi`] (kernel
//! public interface) crate.

use x86::syscall;

use kpi::*;

/// Print `buffer` on the console.
pub fn print(buffer: &str) {
    unsafe {
        let r = syscall!(
            0,
            SystemCall::Print as u64,
            buffer.as_ptr() as u64,
            buffer.len()
        );
        assert!(r == 0x0);
    }
}

/// Exit the process (pass an error `code` to exit).
pub fn exit(code: u64) -> ! {
    unsafe {
        let r = syscall!(0, SystemCall::Exit as u64, code);
        unreachable!()
    }
}

/// Map memory into the address space.
pub fn vspace(op: VSpaceOperation, base: u64, bound: u64) -> u64 {
    unsafe { syscall!(0, SystemCall::VSpace as u64, op as u64, base, bound) }
}
