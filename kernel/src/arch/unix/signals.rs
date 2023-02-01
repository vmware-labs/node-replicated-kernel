// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Platform specific functions to deal with CNR

pub(crate) fn advance_replica(mtid: kpi::system::MachineThreadId, log_id: usize) {
    log::warn!("advance_replica {} {} not implemented", mtid, log_id);
    // All metadata operations are done using log 1. So, make sure that the
    // replica has applied all those operation before any other log sync.
    match crate::fs::cnrfs::MlnrKernelNode::synchronize_log(1) {
        Ok(_) => { /* Simply return */ }
        Err(e) => unreachable!("Error {:?} while advancing the log {}", e, log_id),
    }

    if log_id != 1 {
        match crate::fs::cnrfs::MlnrKernelNode::synchronize_log(log_id) {
            Ok(_) => { /* Simply return */ }
            Err(e) => unreachable!("Error {:?} while advancing the log {}", e, log_id),
        }
    }
}
