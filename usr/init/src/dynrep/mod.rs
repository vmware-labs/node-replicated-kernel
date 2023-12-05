// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use log::info;

use hashbrown::HashMap;

pub fn userspace_dynrep_test() {

    // TODO: types are a placeholder
    // TODO: will want to create with HashMap::with_capacity_in() method
    let mut map: HashMap<usize, usize> = HashMap::new();

    info!("dynrep_test OK");
}
