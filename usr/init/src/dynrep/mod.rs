// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use log::info;

use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
mod allocator;

use allocator::MyAllocator;

static GLOBAL: MyAllocator = MyAllocator;

pub fn userspace_dynrep_test() {
    let _h = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(128, GLOBAL);
    info!("dynrep_test OK");
}
