// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Scheduling logic

use core::intrinsics::unlikely;

use crate::arch::process::ArchProcessManagement;
use crate::arch::timer;
use crate::error::KError;
use crate::nr;
use crate::nr::NR_REPLICA;
use crate::nrproc::NrProcess;
use crate::process::{Executor, ResumeHandle};

/// Runs the process allocated to the given core.
pub(crate) fn schedule() -> ! {
    let apm = ArchProcessManagement;

    // Are we the master/first thread in that replica?
    // Then we should set timer to periodically advance the state
    #[cfg(target_os = "none")]
    let is_replica_main_thread = {
        let thread = atopology::MACHINE_TOPOLOGY.current_thread();
        thread.node().is_none()
            || thread
                .node()
                .unwrap()
                .threads()
                .next()
                .map(|t| t.id == thread.id)
                .unwrap_or(false)
    };
    #[cfg(not(target_os = "none"))]
    let is_replica_main_thread = false;

    // No process assigned to core? Figure out if there is one now:
    if unlikely(!crate::arch::process::has_executor()) {
        if let Some((replica, token)) = NR_REPLICA.get() {
            loop {
                let response = replica.execute(
                    nr::ReadOps::CurrentProcess(*crate::environment::CORE_ID),
                    *token,
                );

                match response {
                    Ok(nr::NodeResult::CoreInfo(ci)) => {
                        let executor =
                            NrProcess::allocate_executor(&apm, ci.pid).expect("This should work");
                        unsafe {
                            (*executor.vcpu_kernel()).resume_with_upcall = ci.entry_point;
                        }

                        // info!("Start execution of {} on gtid {}", executor.eid, gtid);
                        let no = crate::arch::process::swap_current_executor(executor);
                        assert!(no.is_none(), "Handle the case where we replace a process.");
                        if is_replica_main_thread {
                            // Make sure we periodically try and advance the replica on main-thread
                            // even if we're running something (e.g., if everything polls in
                            // user-space we can livelock)
                            timer::set(timer::DEFAULT_TIMER_DEADLINE);
                        }
                        break;
                    }
                    Err(KError::NoExecutorForCore) => {
                        if is_replica_main_thread {
                            // There is no process but we're the "main" thread,
                            // aggressively try and advance the replica
                            let start = rawtime::Instant::now();
                            crate::nrproc::advance_all();
                            crate::arch::advance_fs_replica();

                            if start.elapsed().as_millis() < 1 {
                                // Wait for a bit in case we don't end up doing
                                // any work, otherwise this causes too much
                                // contention and tput drops around ~300k
                                for _i in 0..25_000 {
                                    core::hint::spin_loop();
                                }
                            }
                            continue;
                        } else {
                            // There is no process, set a timer and go to sleep
                            timer::set(timer::DEFAULT_TIMER_DEADLINE);
                        }
                        crate::arch::halt();
                    }
                    other => {
                        unreachable!(
                            "Unexpected return from ReadOps::CurrentExecutor {:?}.",
                            other
                        );
                    }
                };
            }
        }
    }
    debug_assert!(
        crate::arch::process::has_executor(),
        "Require executor next."
    );

    // If we come here, we have a new process, dispatch it:
    unsafe {
        let pe = crate::arch::process::CURRENT_EXECUTOR.borrow();
        let rh = pe.as_ref().expect("Can't borrow current executor").start();
        // Ensure we drop the borrow to `pe` before we resume so we can
        // re-borrow upon syscall/irq entry
        drop(pe);
        rh.resume()
    }
}
