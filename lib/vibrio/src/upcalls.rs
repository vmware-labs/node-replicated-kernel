//! This implementes the user-space side of [scheduler activations][1]
//! to handle the forwarding of traps and interrupts to user-space.
//!
//! Scheduler activations emulate a virtual CPU with critical sections
//! (think interrupts disabled) by having two separate trap areas. Our
//! implementation is very similar to the design in Barrelfish ([see specification][2]
//! and [TLA+ model][3]).
//!
//! [1]: https://dl.acm.org/citation.cfm?id=146944
//! [2]: www.barrelfish.org/publications/TN-010-Spec.pdf
//! [3]: http://www.barrelfish.org/publications/ma-fuchs-tm-mp.pdf

use log::info;

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
pub fn upcall_while_enabled(control: &mut kpi::arch::VirtualCpu, vector: u64, error: u64) -> ! {
    info!(
        "upcall_while_enabled {:?} vec={:#x} err={}",
        control, vector, error
    );

    if vector == 0x2a {
        info!("got networked interrupt...");
        let scheduler = lineup::tls::Environment::scheduler();
        scheduler.add_to_runlist(lineup::ThreadId(1));
    }

    info!("upcall_while_enabled: renable and resume...");
    control.enable_upcalls();
    unsafe { resume(control) }
}

/// A trap (exception or fault) happened while disabled, this is bad and
/// shouldn't happen (i.e., it means there is a bug) in the user-space
/// scheduler logic or upcall handling.
pub fn upcall_while_disabled() -> ! {
    unreachable!("upcall_while_disabled")
}

/// Resume a `state` that was saved by the kernel on a trap or interrupt.
pub unsafe fn resume(control: &mut kpi::arch::VirtualCpu) -> ! {
    // Enable upcalls (Note: we will remain disabled while the instruction pointer
    // is in this function (i.e., between the `resume` and `resume_end`
    // symbol (see asm! below))
    control.enable_upcalls();

    asm! {" // Restore fs and gs registers
            //movq 18*8(%rsi), %rdi
            //wrgsbase %rdi
            //movq 19*8(%rsi), %rdi
            //wrfsbase %rdi

            // Restore vector register
            //fxrstor  20*8(%rsi)

            // Restore CPU registers
            movq  0*8(%rsi), %rax
            movq  1*8(%rsi), %rbx
            movq  2*8(%rsi), %rcx
            movq  3*8(%rsi), %rdx
            // rsi is restored at the end
            movq  5*8(%rsi), %rdi
            movq  6*8(%rsi), %rbp
            movq  7*8(%rsi), %rsp
            movq  8*8(%rsi), %r8
            movq  9*8(%rsi), %r9
            movq 10*8(%rsi), %r10
            movq 11*8(%rsi), %r11
            movq 12*8(%rsi), %r12
            movq 13*8(%rsi), %r13
            movq 14*8(%rsi), %r14
            movq 15*8(%rsi), %r15

            // set up stack for retq below
            pushq 16*8(%rsi)

            // Restore rsi register last, since it was used to reach `state`
            movq  4*8(%rsi), %rsi
            retq

            resume_end:"
    : /* No output */
    :
      "{rsi}" (&control.enabled_state)
    :
    :
    };

    unreachable!("Resume can't go here")
}
