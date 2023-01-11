// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::cmdline::MachineId;

pub(crate) fn get_num_clients() -> u64 {
    (crate::CMDLINE.get().map_or(1, |c| c.workers) - 1) as u64
}

pub(crate) fn get_num_workers() -> u64 {
    crate::CMDLINE.get().map_or(1, |c| c.workers) as u64
}

pub(crate) fn get_machine_id() -> MachineId {
    crate::CMDLINE.get().map_or(1, |c| c.machine_id)
}
