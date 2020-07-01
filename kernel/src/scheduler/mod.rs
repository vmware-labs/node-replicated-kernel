//! Scheduling logic

use crate::kcb::{self, ArchSpecificKcb};
use crate::nr;
use crate::process::Executor;
use crate::process::ResumeHandle;

/// Runs the process allocated to the given core.
pub fn schedule() -> ! {
    let kcb = kcb::get_kcb();
    let replica = kcb.replica.as_ref().expect("Replica not set");

    // Get an executor
    let response = replica.execute_ro(
        nr::ReadOps::CurrentExecutor(kcb.arch.hwthread_id()),
        kcb.replica_idx,
    );
    let executor = match response {
        Ok(nr::NodeResult::Executor(e)) => e,
        e => {
            warn!(
                "Didn't find an executor for the core {:?}, shutting down.",
                e
            );
            crate::arch::debug::shutdown(crate::ExitReason::Ok);
        }
    };

    info!("Created the init process, about to go there...");
    use alloc::sync::Weak;
    let no = kcb::get_kcb()
        .arch
        .swap_current_process(Weak::upgrade(&executor).unwrap());
    assert!(no.is_none());

    unsafe {
        let rh = kcb::get_kcb().arch.current_process().map(|p| p.start());
        rh.unwrap().resume()
    }
}
