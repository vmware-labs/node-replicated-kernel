// Copyright © 2022 VMware, Inc. All Rights Reserved.
// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// architecture specific paddr.
use crate::arch::PAddr;
use crate::arch::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE};

use uefi::table::boot::AllocateType;
use uefi_services::system_table;

pub fn allocate_one_page(typ: uefi::table::boot::MemoryType) -> PAddr {
    let paddr = allocate_pages(1, typ);
    trace!("allocate_one_page {:#x} ", paddr);
    paddr
}

/// Does an allocation of physical memory where the base-address is a multiple of `align_to`.
pub(crate) fn allocate_pages_aligned(
    how_many: usize,
    typ: uefi::table::boot::MemoryType,
    align_to: u64,
) -> PAddr {
    assert!(align_to.is_power_of_two(), "Alignment needs to be pow2");
    assert!(
        align_to >= BASE_PAGE_SIZE as u64,
        "Alignment needs to be at least page-size"
    );

    let alignment_mask = align_to - 1;
    let actual_how_many = how_many + ((align_to as usize) >> BASE_PAGE_SHIFT);
    assert!(actual_how_many >= how_many);

    // The region we allocated
    let paddr = allocate_pages(actual_how_many, typ);
    let end = paddr + (actual_how_many * BASE_PAGE_SIZE);

    // The region within the allocated one we actually want
    let aligned_paddr = PAddr::from((paddr + alignment_mask) & !alignment_mask);
    assert_eq!(aligned_paddr % align_to, 0, "Not aligned properly");
    let aligned_end = aligned_paddr + (how_many * BASE_PAGE_SIZE);

    // How many pages at the bottom and top we need to free
    let unaligned_unused_pages_bottom = (aligned_paddr - paddr).as_usize() / BASE_PAGE_SIZE;
    let unaligned_unused_pages_top = (end - aligned_end).as_usize() / BASE_PAGE_SIZE;

    debug!(
        "Wanted to allocate {} pages but we allocated {} ({:#x} -- {:#x}), keeping range ({:#x} -- {:#x}), freeing #pages at bottom {} and top {}",
        how_many, actual_how_many,
        paddr,
        end,
        aligned_paddr,
        aligned_paddr + (how_many * BASE_PAGE_SIZE),
        unaligned_unused_pages_bottom,
        unaligned_unused_pages_top
    );

    assert!(
        unaligned_unused_pages_bottom + unaligned_unused_pages_top == actual_how_many - how_many,
        "Don't loose any pages"
    );

    // Free unused top and bottom regions again:
    unsafe {
        let st = system_table();
        if unaligned_unused_pages_bottom > 1 {
            st.as_ref()
                .boot_services()
                // This weird API will free the top-most page too? (that's why we do -1)
                // (had a bug where it reused a page from the kernel text as stack)
                .free_pages(paddr.as_u64(), unaligned_unused_pages_bottom - 1)
                .expect("Can't free prev. allocated memory");
        }

        if unaligned_unused_pages_top > 1 {
            st.as_ref()
                .boot_services()
                // Again + page size because I don't know how this API does things
                .free_pages(
                    aligned_end.as_u64() + BASE_PAGE_SIZE as u64,
                    unaligned_unused_pages_top - 1,
                )
                .expect("Can't free prev. allocated memory");
        }
    }

    PAddr::from(aligned_paddr)
}

/// Allocates a set of consecutive physical pages, using UEFI.
///
/// Zeroes the memory we allocate (TODO: I'm not sure if this is already done by UEFI).
/// Returns a `u64` containing the base to that.
pub(crate) fn allocate_pages(how_many: usize, typ: uefi::table::boot::MemoryType) -> PAddr {
    let st = system_table();
    unsafe {
        match st
            .as_ref()
            .boot_services()
            .allocate_pages(AllocateType::AnyPages, typ, how_many)
        {
            Ok(num) => {
                st.as_ref()
                    .boot_services()
                    .set_mem(num as *mut u8, how_many * BASE_PAGE_SIZE, 0u8);
                PAddr::from(num)
            }
            Err(status) => panic!("failed to allocate {:?}", status),
        }
    }
}
