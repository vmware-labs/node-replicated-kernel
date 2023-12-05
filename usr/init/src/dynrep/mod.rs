// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use core::slice::from_raw_parts_mut;
use log::info;

use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use x86::bits64::paging::LARGE_PAGE_SIZE;

mod allocator;

use allocator::MyAllocator;

static GLOBAL: MyAllocator = MyAllocator;

pub fn userspace_dynrep_test() {

    // Allocate a large page of physical memory
    // Note that even if you allocate a base page, behind the scenes a large page is allocated
    // because DCM (and thus DiNOS) only allocates at large page granularity
    // 1 is the client machine id we want to allocate from
    let (frame_id, paddr) = vibrio::syscalls::PhysicalMemory::allocate_large_page(1)
        .expect("Failed to get physical memory large page");
    info!("large frame id={:?}, paddr={:?}", frame_id, paddr);

    // Create base for the mapping
    let base: u64 = 0x0510_0000_0000;

    // Map allocated physical memory into user space so we can actually access it.
    unsafe {
        vibrio::syscalls::VSpace::map_frame(frame_id, base).expect("Failed to map base page");

        // For illustrative purposes, access the frame. You can access it from the ptr base
        let slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, LARGE_PAGE_SIZE);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);
    }

    //let _h = HashMap::<u64, u64, DefaultHashBuilder, MyAllocator>::with_capacity_in(128, GLOBAL);
    info!("dynrep_test OK");
}
