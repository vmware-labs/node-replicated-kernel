use uefi::table::boot::{AllocateType, BootServices, MemoryDescriptor, MemoryType};
use uefi::ResultExt;

use crate::alloc::vec::Vec;
use core::mem;

pub fn memory_map(bt: &BootServices) -> uefi::table::boot::MemoryMapKey {
    // Get an estimate of the memory map size.
    let map_sz = bt.memory_map_size();
    // 8 extra descriptors should be enough.
    let buf_sz = map_sz + 8 * mem::size_of::<MemoryDescriptor>();
    // We will use vectors for convencience.
    let mut buffer = Vec::with_capacity(buf_sz);

    unsafe {
        buffer.set_len(buf_sz);
    }

    let (_key, mut desc_iter) = bt
        .memory_map(&mut buffer)
        .expect_success("Failed to retrieve UEFI memory map");

    // Ensured we have at least one entry.
    // Real memory maps usually have dozens of entries.
    assert!(desc_iter.len() > 0, "Memory map is empty");

    // This is pretty much a sanity test to ensure returned memory isn't filled with random values.
    let first_desc = desc_iter.next().unwrap();
    let phys_start = first_desc.phys_start;
    assert_eq!(phys_start, 0, "Memory does not start at address 0");

    for entry in desc_iter {
        info!(
            "phys addr: {:x} type: {:?} page count: {}",
            entry.phys_start, entry.ty, entry.page_count
        );
    }

    return _key;
}
