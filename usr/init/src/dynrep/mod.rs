// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use log::info;
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

mod allocator;
use allocator::MyAllocator;

pub fn userspace_dynrep_test() {
    let allocator = MyAllocator::default();
    let mut h = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(128, allocator);
    h.insert(1, 2);
    info!("dynrep_test OK");
}
