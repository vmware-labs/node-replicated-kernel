// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Platform specific functions to deal with CNR

pub(crate) fn advance_replica(gtid: atopology::GlobalThreadId, log_id: usize) {
    super::tlb::advance_replica(gtid, log_id)
}
