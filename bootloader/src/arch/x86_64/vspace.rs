// Copyright © 2022 VMware, Inc. All Rights Reserved.
// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! API to construct a virtual address space for the loaded kernel image.
use core::mem::transmute;

use x86::bits64::paging::*;
use x86::controlregs;

use uefi::table::boot::AllocateType;
use uefi_services::system_table;

use crate::kernel::*;
use crate::memory;

use crate::MapAction;

// export the base page size and shifts
pub use x86::bits64::paging::{PAddr, VAddr};
pub use x86::bits64::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE};

impl MapAction {
    /// Transform MapAction into rights for 1 GiB page.
    fn to_pdpt_rights(&self) -> PDPTFlags {
        use MapAction::*;
        match self {
            None => PDPTFlags::empty(),
            ReadUser => PDPTFlags::XD | PDPTFlags::US,
            ReadKernel => PDPTFlags::XD,
            ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteKernel => PDPTFlags::RW | PDPTFlags::XD,
            ReadExecuteUser => PDPTFlags::US,
            ReadExecuteKernel => PDPTFlags::empty(),
            ReadWriteExecuteUser => PDPTFlags::RW | PDPTFlags::US,
            ReadWriteExecuteKernel => PDPTFlags::RW,
        }
    }

    /// Transform MapAction into rights for 2 MiB page.
    fn to_pd_rights(&self) -> PDFlags {
        use MapAction::*;
        match self {
            None => PDFlags::empty(),
            ReadUser => PDFlags::XD | PDFlags::US,
            ReadKernel => PDFlags::XD,
            ReadWriteUser => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteKernel => PDFlags::RW | PDFlags::XD,
            ReadExecuteUser => PDFlags::US,
            ReadExecuteKernel => PDFlags::empty(),
            ReadWriteExecuteUser => PDFlags::RW | PDFlags::US,
            ReadWriteExecuteKernel => PDFlags::RW,
        }
    }

    /// Transform MapAction into rights for 4KiB page.
    fn to_pt_rights(&self) -> PTFlags {
        use MapAction::*;
        match self {
            None => PTFlags::empty(),
            ReadUser => PTFlags::XD | PTFlags::US,
            ReadKernel => PTFlags::XD,
            ReadWriteUser => PTFlags::RW | PTFlags::XD | PTFlags::US,
            ReadWriteKernel => PTFlags::RW | PTFlags::XD,
            ReadExecuteUser => PTFlags::US,
            ReadExecuteKernel => PTFlags::empty(),
            ReadWriteExecuteUser => PTFlags::RW | PTFlags::US,
            ReadWriteExecuteKernel => PTFlags::RW,
        }
    }
}

/// A VSpace allows to create and modify a (virtual) address space.
pub struct VSpaceX86<'a> {
    pub pml4: &'a mut PML4,
}

impl<'a> VSpaceX86<'a> {
    pub fn new() -> VSpaceX86<'a> {
        trace!("Allocate a PML4 (page-table root)");

        let pml4: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        let pml4_table = unsafe { &mut *paddr_to_uefi_vaddr(pml4).as_mut_ptr::<PML4>() };

        VSpaceX86 { pml4: pml4_table }
    }

    pub fn roottable(&self) -> u64 {
        self.pml4 as *const _ as u64
    }

    /// Constructs an identity map but with an offset added to the region.
    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: VAddr,
        pbase: PAddr,
        end: PAddr,
        rights: MapAction,
    ) {
        let vbase = VAddr::from_u64((at_offset + pbase).as_u64());
        let size = (end - pbase).as_usize();
        debug!(
            "map_identity_with_offset {:#x} -- {:#x} -> {:#x} -- {:#x}",
            vbase,
            vbase + size,
            pbase,
            pbase + size
        );
        self.map_generic(vbase, (pbase, size), rights);
    }

    /// Constructs an identity map in this region of memory.
    ///
    /// # Example
    /// `map_identity(0x2000, 0x3000)` will map everything between 0x2000 and 0x3000 to
    /// physical address 0x2000 -- 0x3000.
    pub(crate) fn map_identity(&mut self, base: PAddr, end: PAddr, rights: MapAction) {
        self.map_identity_with_offset(PAddr::from(0x0), base, end, rights);
    }

    /// A pretty generic map function, it puts the physical memory range `pregion` with base and
    /// size into the virtual base at address `vbase`.
    ///
    /// The algorithm tries to allocate the biggest page-sizes possible for the allocations.
    /// We require that `vbase` and `pregion` values are all aligned to a page-size.
    /// TODO: We panic in case there is already a mapping covering the region (should return error).
    pub(crate) fn map_generic(&mut self, vbase: VAddr, pregion: (PAddr, usize), rights: MapAction) {
        let (pbase, psize) = pregion;
        assert_eq!(pbase % BASE_PAGE_SIZE, 0);
        assert_eq!(psize % BASE_PAGE_SIZE, 0);
        assert_eq!(vbase % BASE_PAGE_SIZE, 0);
        assert_ne!(rights, MapAction::None, "TODO: Should we allow that?");

        debug!(
            "map_generic {:#x} -- {:#x} -> {:#x} -- {:#x} {}",
            vbase,
            vbase + psize,
            pbase,
            pbase + psize,
            rights
        );

        let pml4_idx = pml4_index(vbase);
        if !self.pml4[pml4_idx].is_present() {
            trace!("New PDPDT for {:?} @ PML4[{}]", vbase, pml4_idx);
            self.pml4[pml4_idx] = self.new_pdpt();
        }
        assert!(
            self.pml4[pml4_idx].is_present(),
            "The PML4 slot we need was not allocated?"
        );

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let mut pdpt_idx = pdpt_index(vbase);
        // TODO: if we support None mappings, this is if not good enough:
        if !pdpt[pdpt_idx].is_present() {
            // The virtual address corresponding to our position within the page-table
            let vaddr_pos: usize = GIB_512 * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx;

            // In case we can map something at a 1 GiB granularity and
            // we still have at least 1 GiB to map, create huge-page mappings
            if vbase.as_usize() == vaddr_pos
                && (pbase % HUGE_PAGE_SIZE == 0)
                && psize >= HUGE_PAGE_SIZE
            {
                // To track how much space we've covered
                let mut mapped = 0;

                // Add entries to PDPT as long as we're within this allocated PDPT table
                // and have 1 GiB chunks to map:
                while mapped < psize && ((psize - mapped) >= HUGE_PAGE_SIZE) && pdpt_idx < 512 {
                    pdpt[pdpt_idx] = PDPTEntry::new(
                        pbase + mapped,
                        PDPTFlags::P | PDPTFlags::PS | rights.to_pdpt_rights(),
                    );
                    trace!(
                        "Mapped 1GiB range {:#x} -- {:#x} -> {:#x} -- {:#x}",
                        vbase + mapped,
                        (vbase + mapped) + HUGE_PAGE_SIZE,
                        pbase + mapped,
                        (vbase + mapped) + HUGE_PAGE_SIZE
                    );

                    pdpt_idx += 1;
                    mapped += HUGE_PAGE_SIZE;
                }

                if mapped < psize {
                    trace!(
                        "map_generic recurse from 1 GiB map to finish {:#x} -- {:#x} -> {:#x} -- {:#x}",
                        vbase + mapped,
                        vbase + (psize - mapped),
                        (pbase + mapped),
                        pbase + (psize - mapped),
                    );
                    return self.map_generic(
                        vbase + mapped,
                        ((pbase + mapped), psize - mapped),
                        rights,
                    );
                } else {
                    // Everything fit in 1 GiB ranges,
                    // We're done with mappings
                    return;
                }
            } else {
                trace!(
                    "Mapping 0x{:x} -- 0x{:x} is smaller than 1 GiB, going deeper.",
                    vbase,
                    vbase + psize
                );
                pdpt[pdpt_idx] = self.new_pd();
            }
        }
        assert!(
            pdpt[pdpt_idx].is_present(),
            "The PDPT entry we're relying on is not allocated?"
        );
        assert!(
            !pdpt[pdpt_idx].is_page(),
            "An existing mapping already covers the 1 GiB range we're trying to map in?"
        );

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let mut pd_idx = pd_index(vbase);
        if !pd[pd_idx].is_present() {
            let vaddr_pos: usize =
                GIB_512 * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx + LARGE_PAGE_SIZE * pd_idx;

            // In case we can map something at a 2 MiB granularity and
            // we still have at least 2 MiB to map create large-page mappings
            if vbase.as_usize() == vaddr_pos
                && (pbase % LARGE_PAGE_SIZE == 0)
                && psize >= LARGE_PAGE_SIZE
            {
                let mut mapped = 0;
                // Add entries as long as we are within this allocated PDPT table
                // and have at least 2 MiB things to map
                while mapped < psize && ((psize - mapped) >= LARGE_PAGE_SIZE) && pd_idx < 512 {
                    pd[pd_idx] = PDEntry::new(
                        pbase + mapped,
                        PDFlags::P | PDFlags::PS | rights.to_pd_rights(),
                    );
                    trace!(
                        "Mapped 2 MiB region {:#x} -- {:#x} -> {:#x} -- {:#x}",
                        vbase + mapped,
                        (vbase + mapped) + LARGE_PAGE_SIZE,
                        pbase + mapped,
                        (pbase + mapped) + LARGE_PAGE_SIZE
                    );

                    pd_idx += 1;
                    mapped += LARGE_PAGE_SIZE;
                }

                if mapped < psize {
                    trace!(
                        "map_generic recurse from 2 MiB map to finish {:#x} -- {:#x} -> {:#x} -- {:#x}",
                        vbase + mapped,
                        vbase + (psize - mapped),
                        (pbase + mapped),
                        pbase + (psize - mapped),
                    );
                    return self.map_generic(
                        vbase + mapped,
                        ((pbase + mapped), psize - mapped),
                        rights,
                    );
                } else {
                    // Everything fit in 2 MiB ranges,
                    // We're done with mappings
                    return;
                }
            } else {
                trace!(
                    "Mapping 0x{:x} -- 0x{:x} is smaller than 2 MiB, going deeper.",
                    vbase,
                    vbase + psize
                );
                pd[pd_idx] = self.new_pt();
            }
        }
        assert!(
            pd[pd_idx].is_present(),
            "The PD entry we're relying on is not allocated?"
        );
        assert!(
            !pd[pd_idx].is_page(),
            "An existing mapping already covers the 2 MiB range we're trying to map in?"
        );

        let pt = self.get_pt(pd[pd_idx]);
        let mut pt_idx = pt_index(vbase);
        let mut mapped: usize = 0;
        trace!("pt_idx = {} mapped = {} pszie = {}", pt_idx, mapped, psize);
        while mapped < psize && pt_idx < 512 {
            if !pt[pt_idx].is_present() {
                pt[pt_idx] = PTEntry::new(pbase + mapped, PTFlags::P | rights.to_pt_rights());
                trace!("installed 4 KiB mapping: {:?}", pt[pt_idx]);
            } else {
                let vaddr_pos: usize = GIB_512 * pml4_idx
                    + HUGE_PAGE_SIZE * pdpt_idx
                    + LARGE_PAGE_SIZE * pd_idx
                    + BASE_PAGE_SIZE * pt_idx;
                unreachable!(
                    "An existing mapping already covers the 4 KiB range we're trying to map? {:#x} -> {:?} {}",
                    vaddr_pos, pbase + mapped, rights
                );
            }

            mapped += BASE_PAGE_SIZE;
            pt_idx += 1;
        }

        // Need go to different PD/PDPT/PML4 slot
        if mapped < psize {
            trace!(
                "map_generic recurse from 4 KiB map to finish {:#x} -- {:#x} -> {:#x} -- {:#x}",
                vbase + mapped,
                vbase + (psize - mapped),
                (pbase + mapped),
                pbase + (psize - mapped),
            );
            return self.map_generic(vbase + mapped, ((pbase + mapped), psize - mapped), rights);
        }
        // else we're done here, return
    }

    fn new_pt(&mut self) -> PDEntry {
        let paddr: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        PDEntry::new(paddr, PDFlags::P | PDFlags::RW)
    }

    fn new_pd(&mut self) -> PDPTEntry {
        let paddr: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        PDPTEntry::new(paddr, PDPTFlags::P | PDPTFlags::RW)
    }

    fn new_pdpt(&mut self) -> PML4Entry {
        let paddr: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        PML4Entry::new(paddr, PML4Flags::P | PML4Flags::RW)
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt<'b>(&self, entry: PDEntry) -> &'b mut PT {
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_uefi_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd<'b>(&self, entry: PDPTEntry) -> &'b mut PD {
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_uefi_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut PDPT {
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_uefi_vaddr(entry.address())) }
    }

    pub(crate) fn resolve_addr(&self, addr: VAddr) -> Option<PAddr> {
        let pml4_idx = pml4_index(addr);
        if self.pml4[pml4_idx].is_present() {
            let pdpt_idx = pdpt_index(addr);
            let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
            if pdpt[pdpt_idx].is_present() {
                if pdpt[pdpt_idx].is_page() {
                    // Page is a 1 GiB mapping, we have to return here
                    let page_offset = addr.huge_page_offset();
                    return Some(pdpt[pdpt_idx].address() + page_offset);
                } else {
                    let pd_idx = pd_index(addr);
                    let pd = self.get_pd(pdpt[pdpt_idx]);
                    if pd[pd_idx].is_present() {
                        if pd[pd_idx].is_page() {
                            // Encountered a 2 MiB mapping, we have to return here
                            let page_offset = addr.large_page_offset();
                            return Some(pd[pd_idx].address() + page_offset);
                        } else {
                            let pt_idx = pt_index(addr);
                            let pt = self.get_pt(pd[pd_idx]);
                            if pt[pt_idx].is_present() {
                                let page_offset = addr.base_page_offset();
                                return Some(pt[pt_idx].address() + page_offset);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Back a region of virtual address space with
    /// allocated physical memory.
    ///
    ///  * The base should be a multiple of `BASE_PAGE_SIZE`.
    ///  * The size should be a multiple of `BASE_PAGE_SIZE`.
    #[allow(unused)]
    pub fn map(&mut self, base: VAddr, size: usize, rights: MapAction, palignment: u64) {
        assert!(base.is_base_page_aligned(), "base is not page-aligned");
        assert_eq!(size % BASE_PAGE_SIZE, 0, "size is not page-aligned");
        let paddr = memory::allocate_pages_aligned(
            size / BASE_PAGE_SIZE,
            uefi::table::boot::MemoryType(KERNEL_ELF),
            palignment,
        );
        self.map_generic(base, (paddr, size), rights);
    }

    pub unsafe fn dump_table(&self) {
        for (pml_idx, pml_item) in self.pml4.iter().enumerate() {
            if pml_item.is_present() {
                let pdpt_table =
                    transmute::<VAddr, &mut PDPT>(VAddr::from_u64(pml_item.address().as_u64()));

                for (pdpt_idx, pdpt_item) in pdpt_table.iter().enumerate() {
                    if pdpt_item.is_present() {
                        let pd_table = transmute::<VAddr, &mut PD>(VAddr::from_u64(
                            pdpt_item.address().as_u64(),
                        ));
                        if pdpt_item.is_page() {
                            let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                                + (512 * (512 * 0x1000)) * pdpt_idx;

                            info!("PDPT item: vaddr 0x{:x} maps to {:?}", vaddr, pdpt_item);
                        } else {
                            for (pd_idx, pd_item) in pd_table.iter().enumerate() {
                                if pd_item.is_present() {
                                    let ptes = transmute::<VAddr, &mut PT>(VAddr::from_u64(
                                        pd_item.address().as_u64(),
                                    ));

                                    if pd_item.is_page() {
                                        let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                                            + (512 * (512 * 0x1000)) * pdpt_idx
                                            + (512 * 0x1000) * pd_idx;

                                        info!("PD item: vaddr 0x{:x} maps to {:?}", vaddr, pd_item);
                                    } else {
                                        assert!(!pd_item.is_page());
                                        for (pte_idx, pte) in ptes.iter().enumerate() {
                                            let vaddr: usize = (512 * (512 * (512 * 0x1000)))
                                                * pml_idx
                                                + (512 * (512 * 0x1000)) * pdpt_idx
                                                + (512 * 0x1000) * pd_idx
                                                + (0x1000) * pte_idx;

                                            if pte.is_present() {
                                                info!(
                                                    "PT item: vaddr 0x{:x} maps to flags {:?}",
                                                    vaddr, pte
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Debug function to see what's currently in the UEFI address space.
#[allow(unused)]
fn dump_translation_root_register() {
    unsafe {
        let cr_three: u64 = controlregs::cr3();
        debug!("current CR3: {:x}", cr_three);

        let mut pml4: PAddr = PAddr::from(cr_three);
        let mut pml4_table = unsafe { transmute::<VAddr, &mut PML4>(paddr_to_uefi_vaddr(pml4)) };
        let vspace = VSpaceX86 {
            pml4: &mut pml4_table,
        };
        vspace.dump_table();
    }
}
