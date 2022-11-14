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

use crate::arch;
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
        //log::info!("got interrupt cmd={} arg={}", cmd, arg);
        assert!(scheduler.pending_irqs.push(cmd).is_ok());
    } else {
        log::error!("got unknown interrupt... {}", cmd);
    }

    trace!("upcall_while_enabled: renable and resume...");
    unsafe { arch::resume(control) }
}

/// A trap (exception or fault) happened while disabled, this is bad and
/// shouldn't happen (i.e., it means there is a bug) in the user-space
/// scheduler logic or upcall handling.
pub fn upcall_while_disabled() -> ! {
    unreachable!("upcall_while_disabled")
}
