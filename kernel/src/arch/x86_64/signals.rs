// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Platform specific functions to deal with CNR

pub(crate) fn advance_replica(mtid: kpi::system::MachineThreadId, log_id: usize) {
    super::tlb::advance_replica(mtid, log_id)
}
