// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// disable the interrupts
pub fn disable_interrupts() {
    panic!("not yet implemented");
}

pub fn setup_cpu_features() {
    panic!("not yet implemented");
}

pub fn set_translation_table(root: u64) {
    panic!("not yet implemented");
}

/// Make sure the machine supports what we require.
pub fn assert_required_cpu_features() {
    // TODO: add some checks...

    debug!("CPU has all required features, continue");
}
