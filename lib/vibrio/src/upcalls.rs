//! This implementes the user-space side of [scheduler activations][1]
//! to handle the forwarding of traps and interrupts to user-space.
//!
//! Scheduler activations emulate a virtual CPU with critical sections
//! (think interrupts disabled) by having two separate trap areas. Our
//! implementation is very similar to the design in Barrelfish ([see specification][2]).
//!
//! [1]: https://dl.acm.org/citation.cfm?id=146944
//! [2]: www.barrelfish.org/publications/TN-010-Spec.pdf

/// This is invoked through the kernel whenever we get an
/// upcall (trap happened or interrupt came in) we resume
/// exection here so we can handle it accordingly.
///
/// # XXX verify if this is true:
/// When we resume from here we can assume the following:
///
/// * The `enabled` area of [kpi::arch::VirtualCpuState] contains
///   where we left off before we got interrupted.
/// * The [kpi::arch::VirtualCpu] `disabled` flag was set to true and
///   needs to be cleared again.
pub fn upcall_while_enabled() -> ! {
    unreachable!("upcall_while_enabled")
}

/// A trap (exception or fault) happened while disabled, this is bad and
/// shouldn't happen (i.e., it means there is a bug) in the user-space
/// scheduler logic or upcall handling.
pub fn trap_while_disabled() -> ! {
    unreachable!("upcall_while_disabled")
}

/// Resume a `state` that was saved by the kernel on a trap or interrupt.
pub unsafe fn resume(control: &mut kpi::arch::VirtualCpu, state: &kpi::arch::SaveArea) {
    // Enable upcalls (Note: we will remain disabled while the instruction pointer
    // is in this function (i.e., between the `resume` and `resume_end`
    // symbol (see asm! below))
    control.enable_upcalls();

    asm! {" // Restore fs and gs registers
            movq 18*8(%rsi), %rdi
            wrgsbase %rdi
            movq 19*8(%rsi), %rdi
            wrfsbase %rdi

            // Restore vector register
            fxrstor  20*8(%rsi)

            // Restore CPU registers
            movq  0*8(%rsi), %rax
            movq  1*8(%rsi), %rbx
            movq  2*8(%rsi), %rcx
            movq  3*8(%rsi), %rdx
            movq  5*8(%rsi), %rdi
            movq  6*8(%rsi), %rbp
            // %rsp is restored as part of iretq
            movq  8*8(%rsi), %r8
            movq  9*8(%rsi), %r9
            movq 10*8(%r10), %r10
            movq 11*8(%rsi), %r11
            movq 12*8(%rsi), %r12
            movq 13*8(%rsi), %r13
            movq 14*8(%rsi), %r14
            movq 15*8(%rsi), %r15

            // Resume the interrupted function
            pushq      0x1b                // SS
            pushq      7*8(%rsi)           // %rsp
            pushq      17*8(%rsi)          // RFLAGS
            pushq      0x23                // CS
            pushq      16*8(%rsi)          // RIP

            // Restore rsi register last, since it was used to reach `state`
            movq  4*8(%rsi), %rsi

            iretq
            resume_end:"
    : /* No output */
    :
      "rsi" (state)
    :
    :
    };
}
