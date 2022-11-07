// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub(crate) fn advance_replica(gtid: atopology::GlobalThreadId, log_id: usize) {
    log::warn!("NYI: Send AdvanceReplica IPI for {} to {}", log_id, gtid);
}

pub(crate) fn eager_advance_fs_replica() {
    static mut once: bool = false;
    unsafe {
        if !once {
            let core_id = *crate::environment::CORE_ID;
            log::warn!("NYI: eager_advance_fs_replica on core {}", core_id);
            once = true;
        }
    }
}
