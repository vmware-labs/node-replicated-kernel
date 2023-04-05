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

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use lazy_static::lazy_static;
use log::trace;

use kpi::arch::SaveArea;

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
/// execution here so we can handle it accordingly.
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
        //log::info!("got interrupt cmd={} arg={}", cmd, arg);
        assert!(scheduler.pending_irqs.push(cmd).is_ok());
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

    const CS_OFF: usize = 27;
    const SS_OFF: usize = 35;
    asm!("
            // Restore the gs register
            //movq 18*8(%rsi), %rdi
            //wrgsbase %rdi

            // Restore the fs register
            movq {fs_offset}(%rsi), %rdi
            wrfsbase %rdi

            // Restore vector registers
            fxrstor {fxsave_offset}(%rsi)

            // Restore CPU registers
            movq  {rax_offset}(%rsi), %rax
            movq  {rbx_offset}(%rsi), %rbx
            movq  {rcx_offset}(%rsi), %rcx
            movq  {rdx_offset}(%rsi), %rdx
            // %rsi: Restore last (see below) to preserve `save_area`
            movq  {rdi_offset}(%rsi), %rdi
            movq  {rbp_offset}(%rsi), %rbp
            // %rsp: Restored through iretq at the end
            movq  {r8_offset}(%rsi), %r8
            movq  {r9_offset}(%rsi), %r9
            movq {r10_offset}(%rsi), %r10
            movq {r11_offset}(%rsi), %r11
            movq {r12_offset}(%rsi), %r12
            movq {r13_offset}(%rsi), %r13
            movq {r14_offset}(%rsi), %r14
            movq {r15_offset}(%rsi), %r15

            //
            // Set-up stack to return from interrupt
            //

            // SS
            pushq ${ss}
            // %rsp register
            pushq {rsp_offset}(%rsi)
            // rflags register
            pushq {rflags_offset}(%rsi)
            // cs register
            pushq ${cs}
            // %rip
            pushq {rip_offset}(%rsi)

            // Restore rsi register last, since it was used to reach `state`
            movq {rsi_offset}(%rsi), %rsi
            iretq
        ",
        rax_offset = const SaveArea::RAX_OFFSET,
        rbx_offset = const SaveArea::RBX_OFFSET,
        rcx_offset = const SaveArea::RCX_OFFSET,
        rdx_offset = const SaveArea::RDX_OFFSET,
        rsi_offset = const SaveArea::RSI_OFFSET,
        rdi_offset = const SaveArea::RDI_OFFSET,
        rbp_offset = const SaveArea::RBP_OFFSET,
        rsp_offset = const SaveArea::RSP_OFFSET,
        r8_offset = const SaveArea::R8_OFFSET,
        r9_offset = const SaveArea::R9_OFFSET,
        r10_offset = const SaveArea::R10_OFFSET,
        r11_offset = const SaveArea::R11_OFFSET,
        r12_offset = const SaveArea::R12_OFFSET,
        r13_offset = const SaveArea::R13_OFFSET,
        r14_offset = const SaveArea::R14_OFFSET,
        r15_offset = const SaveArea::R15_OFFSET,
        rip_offset = const SaveArea::RIP_OFFSET,
        rflags_offset = const SaveArea::RFLAGS_OFFSET,
        fs_offset = const SaveArea::FS_OFFSET,
        fxsave_offset = const SaveArea::FXSAVE_OFFSET,
        cs = const CS_OFF,
        ss = const SS_OFF,
        in("rsi") &control.enabled_state,
        options(att_syntax, noreturn)
    );
}

/// Well, let's just hope the assembler continues to put this immediatly after
/// `resume()` in the binary...
#[no_mangle]
pub unsafe fn resume_end() {
    unreachable!("resume_end")
}
