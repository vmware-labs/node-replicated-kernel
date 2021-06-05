// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Scheduling logic

use core::intrinsics::unlikely;

use crate::error::KError;
use crate::kcb::{self, ArchSpecificKcb};
use crate::nr;
use crate::nrproc::NrProcess;
use crate::process::{Executor, ResumeHandle};

use crate::arch::timer;

/// Runs the process allocated to the given core.
pub fn schedule() -> ! {
    let kcb = kcb::get_kcb();

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
    if unlikely(kcb.arch.current_executor().is_err()) {
        kcb.replica.as_ref().map(|(replica, token)| {
            loop {
                let response =
                    replica.execute(nr::ReadOps::CurrentProcess(kcb.arch.hwthread_id()), *token);

                match response {
                    Ok(nr::NodeResult::CoreInfo(ci)) => {
                        let executor =
                            NrProcess::allocate_executor(kcb, ci.pid).expect("This should work");
                        unsafe {
                            (*executor.vcpu_kernel()).resume_with_upcall = ci.entry_point;
                        }

                        // info!("Start execution of {} on gtid {}", executor.eid, gtid);
                        let no = kcb::get_kcb().arch.swap_current_executor(executor);
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
                            // There is no process but we're main, aggressively
                            // try and advance the replica
                            for _i in 0..25_000 {
                                core::hint::spin_loop();
                            }

                            // Advance mlnr replica
                            crate::arch::advance_fs_replica();

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
        });
    }
    debug_assert!(
        kcb.arch.current_executor().is_ok(),
        "Require executor next."
    );

    // If we come here, we have a new process, dispatch it:
    unsafe {
        let rh = kcb::get_kcb().arch.current_executor().map(|p| p.start());
        rh.unwrap().resume()
    }
}
