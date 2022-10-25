// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use arrayvec::ArrayVec;
use log::{debug, error, trace};
use uefi::table::boot::MemoryType;

pub use armv8::aarch64::vm::granule4k::{PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

use crate::memory::{global::MAX_PHYSICAL_REGIONS, mcache, Frame};
use crate::KERNEL_ARGS;

// Re-export from the x86 crate
pub use kpi::{MemType, KERNEL_BASE};

/// Translate a kernel 'virtual' address to the physical address of the memory.
pub(crate) fn kernel_vaddr_to_paddr(v: VAddr) -> PAddr {
    let vaddr_val: usize = v.into();
    PAddr::from(vaddr_val as u64 - KERNEL_BASE)
}

/// Translate a physical memory address into a kernel addressable location.
pub(crate) fn paddr_to_kernel_vaddr(p: PAddr) -> VAddr {
    let paddr_val: u64 = p.into();
    VAddr::from((paddr_val + KERNEL_BASE) as usize)
}

/// Set up early memory management
///
/// We walk the memory regions given to us by uefi, since this consumes
/// the UEFI iterator we copy the frames into a `ArrayVec`.
///
/// Ideally, if this works, we should end up with an early FrameCacheSmall
/// that has a small amount of space we can allocate from, and a list of (yet) unmaintained
/// regions of memory.
pub(super) fn process_uefi_memory_regions() -> (
    mcache::FrameCacheEarly,
    ArrayVec<Frame, MAX_PHYSICAL_REGIONS>,
) {
    log::info!("initializing memory management from uefi memory regions");
    let mut emanager: Option<mcache::FrameCacheEarly> = None;
    let mut memory_regions: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
    for region in KERNEL_ARGS
        .get()
        .map(|kargs| &kargs.mm_iter)
        .unwrap_or(&Vec::new())
    {
        let base: PAddr = PAddr::from(region.phys_start);
        let size: usize = region.page_count as usize * BASE_PAGE_SIZE;

        if region.ty == MemoryType::CONVENTIONAL {
            let f = Frame::new(base, size, 0);
            const ONE_MIB: usize = 1 * 1024 * 1024;
            const EARLY_MEMORY_CAPACITY: usize = 32 * 1024 * 1024;
            if base.as_usize() >= ONE_MIB {
                if size > EARLY_MEMORY_CAPACITY && emanager.is_none() {
                    log::info!(
                        "region: [{:016x}..{:016x}] {:?}  (adding as early memory)",
                        base,
                        base + size,
                        region.ty
                    );

                    // This seems like a good frame for the early allocator on
                    // the BSP core. We don't have NUMA information yet so we'd
                    // hope that on a NUMA machine this memory will be on node
                    // 0. Ideally `mem_iter` is ordered by physical address
                    // which would increase our chances, but the UEFI spec
                    // doesn't guarantee anything :S
                    let (early_frame, high) = f.split_at(EARLY_MEMORY_CAPACITY);
                    emanager = Some(mcache::FrameCacheEarly::new_with_frame(0, early_frame));

                    if high != Frame::empty() {
                        assert!(!memory_regions.is_full());
                        memory_regions.push(high);
                    }
                } else {
                    log::info!(
                        "region: [{:016x}..{:016x}] {:?}  (adding as RAM)",
                        base,
                        base + size,
                        region.ty
                    );
                    assert!(!memory_regions.is_full());
                    memory_regions.push(f);
                }
            } else {
                log::info!(
                    "region: [{:016x}..{:016x}] {:?}  (skipping, too small)",
                    base,
                    base + size,
                    region.ty
                );
                // Ignore all physical memory below 1 MiB because it's not worth
                // the hassle of dealing with it Some of the memory here will be
                // used by coreboot, there we just assume the memory is free for
                // us to use -- so in case someone wants to change it have a
                // look there first!
            }
        } else {
            log::info!(
                "region: [{:016x}..{:016x}] {:?}  (skipping, not RAM)",
                base,
                base + size,
                region.ty
            );
        }
    }

    log::info!("done with initializing memory");

    (
        emanager.expect("Couldn't construct an emergency manager (not enough initial memory?)"),
        memory_regions,
    )
}

/// Annotate all physical memory frames we got from UEFI with NUMA affinity by
/// walking through every region `memory_regions` and build subregions that are
/// constructed with the correct NUMA affinity.
///
/// We split frames in `memory_regions` in case they overlap multiple NUMA
/// regions, and let's hope it all fits in `annotated_regions`.
///
/// This really isn't the most efficient algorithm we could've built but we only
/// run this once and don't expect thousands of NUMA nodes or memory regions
/// anyways.
///
/// # Notes
/// There are some implicit assumptions here that a memory region always has
/// just one affinity -- which is also what `topology` assumes.
pub(super) fn identify_numa_affinity(
    memory_regions: ArrayVec<Frame, MAX_PHYSICAL_REGIONS>,
) -> ArrayVec<Frame, MAX_PHYSICAL_REGIONS> {
    log::warn!("Numa affinity not yet supported on aarch64");
    memory_regions
}

/// Initializes persistent memory in the system
///
/// - Discover persistent memory using topology information.
/// - Identity map the persistent memoy regions to user and kernel space.
/// - Find the NUMA-affinity for each persistent memory region.
/// - Use the region and affinity region to bind an allocator to the regions.
pub(super) fn init_persistent_memory() -> ArrayVec<Frame, MAX_PHYSICAL_REGIONS> {
    log::warn!("Persistent memory not yet supported on aarch64");
    ArrayVec::new()
}
