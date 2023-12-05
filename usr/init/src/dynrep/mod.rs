// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use log::info;
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

mod allocator;
use allocator::MyAllocator;

pub const NUM_ENTRIES: u64 = 10_000_000;

pub fn userspace_dynrep_test() {
    let allocator = MyAllocator::default();
    let mut h = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(NUM_ENTRIES as usize, allocator);
    for i in 0..NUM_ENTRIES {
        h.insert(i, i + 1);
    }
    info!("dynrep_test OK");
}
