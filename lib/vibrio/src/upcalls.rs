// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use lazy_static::lazy_static;
use log::trace;

pub static CORES_ONLINE: AtomicUsize = AtomicUsize::new(1);

lazy_static! {
    pub static ref PROCESS_SCHEDULER: lineup::scheduler::SmpScheduler<'static> = {
        #[cfg(feature = "rumprt")]
        {
            lineup::scheduler::SmpScheduler::with_upcalls(lineup::upcalls::Upcalls {
                curlwp: crate::rumprt::rumpkern_curlwp,
                deschedule: crate::rumprt::rumpkern_unsched,
                schedule: crate::rumprt::rumpkern_sched,
                context_switch: crate::rumprt::prt::context_switch,
            })
        }
        #[cfg(not(feature = "rumprt"))]
        {
            lineup::scheduler::SmpScheduler::default()
        }
    };
}

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
pub fn upcall_while_enabled(control: &mut kpi::arch::VirtualCpu, cmd: u64, arg: u64) -> ! {
    trace!(
        "upcall_while_enabled {:?} vec={:#x} err={}",
        control,
        cmd,
        arg
    );

    let sched = &PROCESS_SCHEDULER;

    if cmd == kpi::upcall::NEW_CORE {
        use lineup::tls2::SchedulerControlBlock;
        let core_id = arg;
        log::info!("Got a new core ({}) assigned to us.", core_id);
        CORES_ONLINE.fetch_add(1, Ordering::SeqCst);

        #[cfg(feature = "rumprt")]
        {
            use crate::rumprt::crt::READY_TO_RUMBLE;
            while READY_TO_RUMBLE.load(Ordering::SeqCst) == false {
                core::hint::spin_loop();
            }
        }

        let scb: SchedulerControlBlock = SchedulerControlBlock::new(core_id as usize);
        loop {
            sched.run(&scb);
        }
    }

    if cmd == 0x2a || cmd == 0x24 {
        // TODO(correctness): this will use `gs` to access the SchedulerControlBlock
        // that assumes that we have already called scheduler.run() and we preserve
        // the SchedulerControlBlock register even if we return from run()
        let scheduler = lineup::tls2::Environment::scheduler();
        log::info!("got interrupt cmd={} arg={}", cmd, arg);
        scheduler.pending_irqs.push(cmd).map_err(|_e| {
            log::error!("Overflowed pending_irqs, missed cmd={} arg={}", cmd, arg);
        });
    } else {
        log::error!("got unknown interrupt... {}", cmd);
    }

    trace!("upcall_while_enabled: renable and resume...");
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
    //debug!("resume enabled_state {:p}", &control.enabled_state);

    llvm_asm! {"
            // Restore gs
            //movq 18*8(%rsi), %rdi
            //wrgsbase %rdi

            // Restore fs
            movq 19*8(%rsi), %rdi
            wrfsbase %rdi

            // Restore vector register
            fxrstor 24*8(%rsi)

            // Restore CPU registers
            movq  0*8(%rsi), %rax
            movq  1*8(%rsi), %rbx
            movq  2*8(%rsi), %rcx
            movq  3*8(%rsi), %rdx
            // rsi is restored at the end (before iretq)
            movq  5*8(%rsi), %rdi
            movq  6*8(%rsi), %rbp
            // rsp is restored through iretq at the end
            movq  8*8(%rsi), %r8
            movq  9*8(%rsi), %r9
            movq 10*8(%rsi), %r10
            movq 11*8(%rsi), %r11
            movq 12*8(%rsi), %r12
            movq 13*8(%rsi), %r13
            movq 14*8(%rsi), %r14
            movq 15*8(%rsi), %r15

            //
            // Set-up stack to return from interrupt
            //

            // SS
            pushq $$35
            // %rsp
            pushq 7*8(%rsi)
            // RFLAGS
            pushq 17*8(%rsi)
            // code-segment
            pushq $$27
            // %rip
            pushq 16*8(%rsi)
            // Restore rsi register last, since it was used to reach `state`
            movq 4*8(%rsi), %rsi
            iretq
            .global resume_end
            resume_end:"
    : /* No output */
    :
      "{rsi}" (&control.enabled_state)
    :
    :
    };

    unreachable!("Resume can't go here")
}
