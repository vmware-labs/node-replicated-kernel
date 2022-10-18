// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Function and definitions that are specific to how the
//! x86-64 address space is laid out.

use alloc::vec::Vec;

use arrayvec::ArrayVec;
use log::{debug, error, trace};
use uefi::table::boot::MemoryType;

use crate::memory::vspace::MapAction;
use crate::memory::{global::MAX_PHYSICAL_REGIONS, mcache, Frame};
use crate::KERNEL_ARGS;

use super::vspace;

// Re-export from the x86 crate
pub use kpi::{MemType, KERNEL_BASE};
pub use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

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
    let mut annotated_regions = ArrayVec::new();

    if atopology::MACHINE_TOPOLOGY.num_nodes() > 0 {
        for orig_frame in memory_regions.iter() {
            for node in atopology::MACHINE_TOPOLOGY.nodes() {
                // trying to find a NUMA memory affinity that contains the given `orig_frame`
                for affinity_region in node.memory() {
                    if !affinity_region.is_hotplug_region() {
                        match affinity_region
                            .contains(orig_frame.base.into(), orig_frame.end().into())
                        {
                            (_, mid, _) => {
                                if mid.0 > 0 {
                                    let mid_paddr = (PAddr::from(mid.0), PAddr::from(mid.1));
                                    let annotated_frame = Frame::from_range(mid_paddr, node.id);
                                    trace!("Identified NUMA region for {:?}", annotated_frame);
                                    assert!(!annotated_regions.is_full());
                                    annotated_regions.push(annotated_frame);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // We are not running on a NUMA machine,
        // so we just assume everything as node#0
        // (and copy from original memory regions):
        annotated_regions
            .try_extend_from_slice(memory_regions.as_slice())
            .expect("Can't initialize annotated regions");
    }

    // Sanity check our code the sum of total bytes in `annotated_regions`
    // should be the equal to the sum of bytes in `memory_regions`:
    assert_eq!(
        annotated_regions.iter().fold(0, |sum, f| sum + f.size()),
        memory_regions.iter().fold(0, |sum, f| sum + f.size())
    );

    annotated_regions
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
    let mut emanager: Option<mcache::FrameCacheEarly> = None;
    let mut memory_regions: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
    for region in KERNEL_ARGS
        .get()
        .map(|kargs| &kargs.mm_iter)
        .unwrap_or(&Vec::new())
    {
        if region.ty == MemoryType::CONVENTIONAL {
            debug!("Found physical memory region {:?}", region);

            let base: PAddr = PAddr::from(region.phys_start);
            let size: usize = region.page_count as usize * BASE_PAGE_SIZE;
            let f = Frame::new(base, size, 0);

            const ONE_MIB: usize = 1 * 1024 * 1024;
            const EARLY_MEMORY_CAPACITY: usize = 32 * 1024 * 1024;
            if base.as_usize() >= ONE_MIB {
                if size > EARLY_MEMORY_CAPACITY && emanager.is_none() {
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
                    assert!(!memory_regions.is_full());
                    memory_regions.push(f);
                }
            } else {
                // Ignore all physical memory below 1 MiB because it's not worth
                // the hassle of dealing with it Some of the memory here will be
                // used by coreboot, there we just assume the memory is free for
                // us to use -- so in case someone wants to change it have a
                // look there first!
            }
        }
    }

    (
        emanager.expect("Couldn't construct an emergency manager (not enough initial memory?)"),
        memory_regions,
    )
}

/// Map the persistent memory addresses to the vspace.
///
/// # TODO
/// This is a temporary hack until the bootloader shows us the persistent regions
/// when we query the uefi memory map. For some reason they don't show up with
/// current qemu edk2 OVMF builds. So we query ACPI directly here to find them.
fn map_physical_persistent_memory() {
    use atopology::MemoryType;
    let desc_iter = atopology::MACHINE_TOPOLOGY.persistent_memory();
    for entry in desc_iter {
        if entry.phys_start == 0x0 {
            debug!("Don't map memory entry at physical zero? {:#?}", entry);
            continue;
        }

        // Compute physical base and size for the region we're about to map
        let phys_range_start = PAddr::from(entry.phys_start);
        let size = entry.page_count as usize * BASE_PAGE_SIZE;
        let phys_range_end =
            PAddr::from(entry.phys_start + entry.page_count * BASE_PAGE_SIZE as u64);

        if phys_range_start.as_u64() <= 0xfee00000u64 && phys_range_end.as_u64() >= 0xfee00000u64 {
            debug!("{:?} covers APIC range, ignore for now.", entry);
            continue;
        }

        let rights: MapAction = match entry.ty {
            MemoryType::PERSISTENT_MEMORY => MapAction::kernel() | MapAction::write(),
            _ => {
                error!("Unknown memory type, what should we do? {:#?}", entry);
                MapAction::none()
            }
        };

        debug!(
            "Doing {:?} on {:#x} -- {:#x}",
            rights, phys_range_start, phys_range_end
        );
        if rights != MapAction::none() && entry.ty == MemoryType::PERSISTENT_MEMORY {
            vspace::INITIAL_VSPACE
                .lock()
                .map_identity(phys_range_start, size, rights)
                .expect("Unable to add PMem address to user-space");

            vspace::INITIAL_VSPACE
                .lock()
                .map_identity_with_offset(PAddr::from(KERNEL_BASE), phys_range_start, size, rights)
                .expect("Unable to add PMem address to Kernel-space");
        }
    }
}

/// Initializes persistent memory in the system
///
/// - Discover persistent memory using topology information.
/// - Identity map the persistent memoy regions to user and kernel space.
/// - Find the NUMA-affinity for each persistent memory region.
/// - Use the region and affinity region to bind an allocator to the regions.
pub(super) fn init_persistent_memory() -> ArrayVec<Frame, MAX_PHYSICAL_REGIONS> {
    map_physical_persistent_memory();

    let mut memory_regions: ArrayVec<Frame, MAX_PHYSICAL_REGIONS> = ArrayVec::new();
    let mut pmem_iter = atopology::MACHINE_TOPOLOGY.persistent_memory();
    for region in &mut pmem_iter {
        if region.ty == atopology::MemoryType::PERSISTENT_MEMORY {
            debug!("Found physical memory region {:?}", region);

            let base: PAddr = PAddr::from(region.phys_start);
            let size: usize = region.page_count as usize * BASE_PAGE_SIZE;
            let f = Frame::new(base, size, 0);

            assert!(!memory_regions.is_full());
            memory_regions.push(f);
        }
    }
    let mut annotated_regions = identify_numa_affinity(memory_regions);
    annotated_regions.sort_unstable_by(|&a, &b| a.affinity.partial_cmp(&b.affinity).unwrap());

    annotated_regions
}
