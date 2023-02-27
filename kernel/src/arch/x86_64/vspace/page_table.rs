// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::alloc::Layout;
use core::mem::transmute;
use core::pin::Pin;
use core::ptr::NonNull;

use kpi::KERNEL_BASE;
use log::{debug, trace};
use x86::bits64::paging::*;

use crate::error::KError;
use crate::memory::detmem::DA;
use crate::memory::vspace::*;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, Frame, PAddr, VAddr};

/// Describes a potential modification operation on existing page tables.
pub(super) const PT_LAYOUT: Layout =
    unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE) };
// Safety (size not overflowing when rounding up is given with size == align):
static_assertions::const_assert!(BASE_PAGE_SIZE > 0); // align must not be zero
static_assertions::const_assert!(BASE_PAGE_SIZE.is_power_of_two()); // align must be a power of two

/// A modification operation on the PageTable.
enum Modify {
    /// Change rights of mapping to new MapAction.
    UpdateRights(MapAction),
    /// Remove frame from page-table.
    Unmap,
}

/// The actual page-table. We allocate the PML4 upfront.
pub(crate) struct PageTable {
    pub pml4: Pin<Box<PML4>>,
    pub da: Option<DA>,
}

impl Drop for PageTable {
    fn drop(&mut self) {
        use alloc::alloc::dealloc;

        // Do a DFS and free all page-table memory allocated below kernel-base,
        // don't free the mapped frames -- we return them later through NR
        for pml4_idx in 0..PAGE_SIZE_ENTRIES {
            if pml4_idx < pml4_index(KERNEL_BASE.into()) && self.pml4[pml4_idx].is_present() {
                for pdpt_idx in 0..PAGE_SIZE_ENTRIES {
                    let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
                    if pdpt[pdpt_idx].is_present() {
                        if !pdpt[pdpt_idx].is_page() {
                            for pd_idx in 0..PAGE_SIZE_ENTRIES {
                                let pd = self.get_pd(pdpt[pdpt_idx]);
                                if pd[pd_idx].is_present() {
                                    if !pd[pd_idx].is_page() {
                                        for pt_idx in 0..PAGE_SIZE_ENTRIES {
                                            let pt = self.get_pt(pd[pd_idx]);
                                            if pt[pt_idx].is_present() {}
                                        }
                                        // Free this PT (page-table)
                                        let addr = pd[pd_idx].address();
                                        let vaddr = paddr_to_kernel_vaddr(addr);
                                        unsafe { dealloc(vaddr.as_mut_ptr(), PT_LAYOUT) };
                                    }
                                } else {
                                    // Encountered a 2 MiB mapping, nothing to free
                                }
                            }
                            // Free this PDPT entry (PD page-table)
                            let addr = pdpt[pdpt_idx].address();
                            let vaddr = paddr_to_kernel_vaddr(addr);
                            unsafe { dealloc(vaddr.as_mut_ptr(), PT_LAYOUT) };
                        } else {
                            // Encountered Page is a 1 GiB mapping, nothing to free
                        }
                    }
                }

                // Free this PML4 entry (PDPT page-table)
                let addr = self.pml4[pml4_idx].address();
                let vaddr = paddr_to_kernel_vaddr(addr);
                unsafe { dealloc(vaddr.as_mut_ptr(), PT_LAYOUT) };
                self.pml4[pml4_idx] = PML4Entry(0x0);
            }
        }
    }
}

impl AddressSpace for PageTable {
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError> {
        // These assertion are checked with error returns in `VSpace`
        debug_assert!(frame.size() > 0);
        debug_assert_eq!(
            frame.base % frame.size(),
            0,
            "paddr should be aligned to page-size"
        );
        debug_assert_eq!(
            base % frame.size(),
            0,
            "vaddr should be aligned to page-size"
        );

        self.map_generic(base, (frame.base, frame.size()), action, true)
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        // TODO(correctness): Calculate this properly
        20
    }

    fn adjust(&mut self, vaddr: VAddr, rights: MapAction) -> Result<(VAddr, usize), KError> {
        if !vaddr.is_base_page_aligned() {
            return Err(KError::InvalidBase);
        }
        let (vaddr, _paddr, size, _old_rights) =
            self.modify_generic(vaddr, Modify::UpdateRights(rights))?;
        Ok((vaddr, size))
    }

    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), KError> {
        let pml4_idx = pml4_index(addr);
        if self.pml4[pml4_idx].is_present() {
            let pdpt_idx = pdpt_index(addr);
            let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
            if pdpt[pdpt_idx].is_present() {
                if pdpt[pdpt_idx].is_page() {
                    // Page is a 1 GiB mapping, we have to return here
                    let page_offset = addr.huge_page_offset();
                    let paddr = pdpt[pdpt_idx].address() + page_offset;
                    let flags: MapAction = pdpt[pdpt_idx].flags().into();
                    return Ok((paddr, flags));
                } else {
                    let pd_idx = pd_index(addr);
                    let pd = self.get_pd(pdpt[pdpt_idx]);
                    if pd[pd_idx].is_present() {
                        if pd[pd_idx].is_page() {
                            // Encountered a 2 MiB mapping, we have to return here
                            let page_offset = addr.large_page_offset();
                            let paddr = pd[pd_idx].address() + page_offset;
                            let flags: MapAction = pd[pd_idx].flags().into();
                            return Ok((paddr, flags));
                        } else {
                            let pt_idx = pt_index(addr);
                            let pt = self.get_pt(pd[pd_idx]);
                            if pt[pt_idx].is_present() {
                                let page_offset = addr.base_page_offset();
                                let paddr = pt[pt_idx].address() + page_offset;
                                let flags: MapAction = pt[pt_idx].flags().into();
                                return Ok((paddr, flags));
                            }
                        }
                    }
                }
            }
        }

        // else:
        Err(KError::NotMapped)
    }

    fn unmap(&mut self, base: VAddr) -> Result<TlbFlushHandle, KError> {
        if !base.is_base_page_aligned() {
            return Err(KError::InvalidBase);
        }
        let (vaddr, paddr, size, rights) = self.modify_generic(base, Modify::Unmap)?;
        Ok(TlbFlushHandle::new(vaddr, paddr, size, rights))
    }
}

impl PageTable {
    /// Create a new address-space.
    ///
    /// Allocate an initial PML4 table for it.
    pub(crate) fn new(da: DA) -> Result<PageTable, KError> {
        let pml4 = Box::try_new(
            [PML4Entry::new(PAddr::from(0x0u64), PML4Flags::empty()); PAGE_SIZE_ENTRIES],
        )?;

        Ok(PageTable {
            pml4: Box::into_pin(pml4),
            da: Some(da),
        })
    }

    pub(crate) fn pml4_address(&self) -> PAddr {
        let pml4_vaddr = VAddr::from(&*self.pml4 as *const _ as u64);
        kernel_vaddr_to_paddr(pml4_vaddr)
    }

    /// Constructs an identity map but with an offset added to the region.
    ///
    /// This can be useful for example to map physical memory above `KERNEL_BASE`.
    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: PAddr,
        pbase: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        assert!(at_offset.is_base_page_aligned());
        assert!(pbase.is_base_page_aligned());
        assert_eq!(size % BASE_PAGE_SIZE, 0, "Size not a multiple of page-size");

        let vbase = VAddr::from_u64((at_offset + pbase).as_u64());
        debug!(
            "map_identity_with_offset {:#x} -- {:#x} -> {:#x} -- {:#x}",
            vbase,
            vbase + size,
            pbase,
            pbase + size
        );

        self.map_generic(vbase, (pbase, size), rights, true)
    }

    /// Identity maps a given physical memory range [`base`, `base` + `size`]
    /// in the address space.
    pub(crate) fn map_identity(
        &mut self,
        base: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        self.map_identity_with_offset(PAddr::from(0x0), base, size, rights)
    }

    /// Retrieves the relevant PDPT table for a given virtual address `vbase`.
    ///
    /// Allocates the PDPT page if it doesn't exist yet.
    fn get_or_alloc_pdpt(&mut self, vbase: VAddr) -> &mut PDPT {
        let pml4_idx = pml4_index(vbase);
        if !self.pml4[pml4_idx].is_present() {
            trace!("Need new PDPDT for {:?} @ PML4[{}]", vbase, pml4_idx);
            self.pml4[pml4_idx] = self.new_pdpt();
        }
        assert!(
            self.pml4[pml4_idx].is_present(),
            "The PML4 slot we need was not allocated?"
        );

        self.get_pdpt_mut(self.pml4[pml4_idx])
    }

    /// Check if we can just insert a huge page for the current mapping
    fn can_map_as_huge_page(
        &mut self,
        pml4_entry: PML4Entry,
        pbase: PAddr,
        psize: usize,
        vbase: VAddr,
        _rights: MapAction,
    ) -> bool {
        let pml4_idx = pml4_index(vbase);
        let pdpt_idx = pdpt_index(vbase);
        let pdpt_entry = {
            let pdpt = self.get_pdpt(pml4_entry);
            pdpt[pdpt_idx]
        };

        // The virtual address corresponding to the current position within the page-table
        let vaddr_pos: VAddr = VAddr::from(PML4_SLOT_SIZE * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx);

        let want_to_map_here = vbase == vaddr_pos;
        let physical_frame_is_aligned = pbase.is_huge_page_aligned();
        let want_to_map_at_least_1gib = psize >= HUGE_PAGE_SIZE;

        if !want_to_map_here || !physical_frame_is_aligned || !want_to_map_at_least_1gib {
            return false;
        }

        let no_underlying_2mib_mappings = if !pdpt_entry.is_present() {
            true
        } else {
            // We go and check if the underlying page-table is emtpy
            // (previous mappings could've left a PD here which since has been emptied)
            // TODO(efficiency): If we had 4 KiB mappings (that are empty below the PD) we
            // don't currently detect that.
            let mut all_entries_empty: bool = true;
            let pd = self.get_pd(pdpt_entry);
            for i in 0..pd.len() {
                all_entries_empty &= !pd[i].is_present();
            }

            if all_entries_empty {
                // Reclaim PD page back to pager
                // warn!("TODO: pager.release_base_page()");
                let pdpt = self.get_pdpt_mut(pml4_entry);
                pdpt[pdpt_idx] = PDPTEntry::new(PAddr::from(0x0), PDPTFlags::empty());
            }

            all_entries_empty
        };

        no_underlying_2mib_mappings
    }

    /// Check if we can just insert a large page for the current mapping
    fn can_map_as_large_page(
        &mut self,
        pdpt_entry: PDPTEntry,
        pbase: PAddr,
        psize: usize,
        vbase: VAddr,
        _rights: MapAction,
    ) -> bool {
        let pml4_idx = pml4_index(vbase);
        let pdpt_idx = pdpt_index(vbase);
        let pd_idx = pd_index(vbase);
        let pd_entry = {
            let pd = self.get_pd(pdpt_entry);
            pd[pd_idx]
        };

        // The virtual address corresponding to the current position within the page-table
        let vaddr_pos: VAddr = VAddr::from(
            PML4_SLOT_SIZE * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx + LARGE_PAGE_SIZE * pd_idx,
        );

        let want_to_map_here = vbase == vaddr_pos;
        let physical_frame_is_aligned = pbase % LARGE_PAGE_SIZE == 0;
        let want_to_map_at_least_2mib = psize >= LARGE_PAGE_SIZE;

        if !want_to_map_here || !physical_frame_is_aligned || !want_to_map_at_least_2mib {
            return false;
        }

        let no_underlying_4kib_mappings = if !pd_entry.is_present() {
            true
        } else {
            // We go and check if the underlying page-table is emtpy
            // (previous mappings could've left a PT here which since has been emptied)
            let mut all_entries_empty: bool = true;
            let pt = self.get_pt(pd_entry);
            for i in 0..pt.len() {
                all_entries_empty &= !pt[i].is_present();
            }

            if all_entries_empty {
                // Reclaim PT page back to pager
                //warn!("TODO: pager.release_base_page()");
                let pd = self.get_pd_mut(pdpt_entry);
                pd[pd_idx] = PDEntry::new(PAddr::from(0x0), PDFlags::empty());
            }
            all_entries_empty
        };

        no_underlying_4kib_mappings
    }

    /// Starts to insert huge-pages for `vbase` at the given `pdpt_idx`.
    fn insert_huge_mappings(
        &mut self,
        mut pdpt_idx: usize,
        vbase: VAddr,
        pbase: PAddr,
        psize: usize,
        rights: MapAction,
        insert_mapping: bool,
    ) -> Result<(), KError> {
        let pdpt = self.get_or_alloc_pdpt(vbase);

        // To track how much space we've mapped so far
        let mut mapped = 0;

        // Add entries to PDPT as long as we're within this allocated PDPT table
        // and have 1 GiB chunks to map:
        while mapped < psize && ((psize - mapped) >= HUGE_PAGE_SIZE) && pdpt_idx < pdpt.len() {
            if !insert_mapping {
                // Check if we could map in theory (no overlap)
                if pdpt[pdpt_idx].is_present() {
                    let address = pdpt[pdpt_idx].address();
                    let cur_rights: MapAction = pdpt[pdpt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        // Return an error if a frame is present,
                        // and it's not exactly the frame+rights combo we're
                        // trying to map
                        return Err(KError::AlreadyMapped {
                            base: vbase + mapped,
                        });
                    }
                }
            } else {
                if pdpt[pdpt_idx].is_present() {
                    let address = pdpt[pdpt_idx].address();
                    let cur_rights: MapAction = pdpt[pdpt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        panic!("Trying to map 1 GiB page but it conflicts with existing mapping");
                    }
                }

                // Construct a 1 GiB mapping to `pbase` + `mapped`, mark it as present and 1 GiB sized
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
            }

            pdpt_idx += 1;
            mapped += HUGE_PAGE_SIZE;
        }
        assert!(mapped <= psize);

        if mapped == psize {
            // Everything fit in 1 GiB pages and within the same PDPT, we're done with mappings
            return Ok(());
        } else {
            // mapped < psize: Need to map more (either as 2 MiB or 4 KiB pages or continue on the
            // next PDPT)
            trace!(
                "insert_huge_mappings recurse to map_generic to finish {:#x} -- {:#x} -> {:#x} -- {:#x}",
                vbase + mapped,
                vbase + (psize - mapped),
                (pbase + mapped),
                pbase + (psize - mapped),
            );

            return self.map_generic(
                vbase + mapped,
                ((pbase + mapped), psize - mapped),
                rights,
                insert_mapping,
            );
        }
    }

    /// Starts to insert large-pages for `vbase` at the given `pd_idx`.
    fn insert_large_mappings(
        &mut self,
        pdpt_entry: PDPTEntry,
        vbase: VAddr,
        pbase: PAddr,
        psize: usize,
        rights: MapAction,
        insert_mapping: bool,
    ) -> Result<(), KError> {
        let mut pd_idx = pd_index(vbase);
        let pd = self.get_pd_mut(pdpt_entry);

        // To track how much space we've mapped so far
        let mut mapped = 0;

        // Add entries as long as we are within this allocated PDPT table
        // and have at least 2 MiB things to map
        while mapped < psize && ((psize - mapped) >= LARGE_PAGE_SIZE) && pd_idx < pd.len() {
            if !insert_mapping {
                // Check if we could map in theory (no overlap)
                if pd[pd_idx].is_present() {
                    let address = pd[pd_idx].address();
                    let cur_rights: MapAction = pd[pd_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        // Return an error if a frame is present,
                        // and it's not exactly the frame+rights combo we're
                        // trying to map anyways
                        return Err(KError::AlreadyMapped {
                            base: vbase + mapped,
                        });
                    }
                }
            } else {
                if pd[pd_idx].is_present() {
                    let address = pd[pd_idx].address();
                    let cur_rights: MapAction = pd[pd_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        panic!("Trying to map 2 MiB page but it conflicts with existing mapping");
                    }
                }

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
            }

            pd_idx += 1;
            mapped += LARGE_PAGE_SIZE;
        }
        assert!(mapped <= psize);

        if mapped == psize {
            // Everything fit in 2 MiB pages and within the same PD, we're done with mappings
            return Ok(());
        } else {
            // mapped < psize: Need to map more (as 4 KiB pages or continue on the
            // next PD)
            trace!(
                "insert_large_mappings recurse to map_generic to finish {:#x} -- {:#x} -> {:#x} -- {:#x}",
                vbase + mapped,
                vbase + (psize - mapped),
                (pbase + mapped),
                pbase + (psize - mapped),
            );

            return self.map_generic(
                vbase + mapped,
                ((pbase + mapped), psize - mapped),
                rights,
                insert_mapping,
            );
        }
    }

    /// Starts to insert base-pages for `vbase` at the given `pt_idx`.
    fn insert_base_mappings(
        &mut self,
        pd_entry: PDEntry,
        vbase: VAddr,
        pbase: PAddr,
        psize: usize,
        rights: MapAction,
        insert_mapping: bool,
    ) -> Result<(), KError> {
        let pt = self.get_pt_mut(pd_entry);
        let mut pt_idx = pt_index(vbase);

        // To track how much space we've mapped so far
        let mut mapped: usize = 0;
        while mapped < psize && pt_idx < pt.len() {
            if !insert_mapping {
                // Check if we could map in theory (no overlap)
                if pt[pt_idx].is_present() {
                    let address = pt[pt_idx].address();
                    let cur_rights: MapAction = pt[pt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        // Return an error if a frame is present,
                        // and it's not exactly the frame+rights combo we're
                        // trying to map anyways
                        return Err(KError::AlreadyMapped {
                            base: vbase + mapped,
                        });
                    }
                }
            } else {
                if pt[pt_idx].is_present() {
                    let address = pt[pt_idx].address();
                    let cur_rights: MapAction = pt[pt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        panic!(
                            "Trying to map 4 KiB page but it conflicts with existing mapping {:x}",
                            address
                        );
                    }
                }

                pt[pt_idx] = PTEntry::new(pbase + mapped, PTFlags::P | rights.to_pt_rights());
            }

            mapped += BASE_PAGE_SIZE;
            pt_idx += 1;
        }
        assert!(mapped <= psize);

        if mapped == psize {
            // Everything fit in 4 KiB pages and within the same PT, we're done with mappings
            return Ok(());
        } else {
            // mapped < psize: Need to map more (as 4 KiB pages or continue on the
            // next PD)

            trace!(
                "insert_base_mappings recurse to map_generic to finish {:#x} -- {:#x} -> {:#x} -- {:#x}",
                vbase + mapped,
                vbase + (psize - mapped),
                (pbase + mapped),
                pbase + (psize - mapped),
            );

            return self.map_generic(
                vbase + mapped,
                ((pbase + mapped), psize - mapped),
                rights,
                insert_mapping,
            );
        }
    }

    /// A pretty generic map function, it puts the physical memory range
    /// `pregion` with base and size into the virtual base at address `vbase`.
    ///
    /// The function will try to allocate memory for page-tables as needed by
    /// using the supplied `pager`.
    ///
    /// The function tries to allocate the biggest possible pages for the allocations
    /// (1 GiB, 2 MiB, 4 KiB). We require that `vbase` and `pregion` values are all aligned
    /// to a base-page.
    ///
    /// Will return an error in case a existing mapping already exists (and is not the same)
    /// at a given location we're trying to map.
    pub(crate) fn map_generic(
        &mut self,
        vbase: VAddr,
        pregion: (PAddr, usize),
        rights: MapAction,
        insert_mapping: bool,
    ) -> Result<(), KError> {
        let (pbase, psize) = pregion;
        assert!(pbase.is_base_page_aligned());
        assert!(vbase.is_base_page_aligned());
        assert_eq!(psize % BASE_PAGE_SIZE, 0);

        debug!(
            "map_generic {:#x} -- {:#x} -> {:#x} -- {:#x} {}",
            vbase,
            vbase + psize,
            pbase,
            pbase + psize,
            rights
        );

        let pml4_idx = pml4_index(vbase);
        let pdpt = self.get_or_alloc_pdpt(vbase);
        let pdpt_idx = pdpt_index(vbase);
        let pdpt_entry = pdpt[pdpt_idx];
        drop(pdpt);

        let pml4_entry = self.pml4[pml4_idx];
        if self.can_map_as_huge_page(pml4_entry, pbase, psize, vbase, rights) {
            // Start inserting mappings here in case we can map something as 1 GiB pages
            return self.insert_huge_mappings(
                pdpt_idx,
                vbase,
                pbase,
                psize,
                rights,
                insert_mapping,
            );
        } else if !pdpt_entry.is_present() {
            trace!(
                "Mapping 0x{:x} -- 0x{:x} is smaller than 1 GiB, going deeper.",
                vbase,
                vbase + psize
            );
            let pd = self.new_pd();
            let pdpt = self.get_pdpt_mut(pml4_entry);
            pdpt[pdpt_idx] = pd;
        }

        let pdpt = self.get_pdpt(pml4_entry);
        let pdpt_entry = pdpt[pdpt_idx];
        drop(pdpt);

        assert!(
            pdpt[pdpt_idx].is_present(),
            "The PDPT entry we're relying on is not allocated?"
        );

        if pdpt[pdpt_idx].is_page() {
            if !insert_mapping {
                // Check if we could map in theory (no overlap)
                return Err(KError::AlreadyMapped { base: vbase });
            } else {
                panic!(
                    "An existing mapping already covers the 1 GiB range we're trying to map in (vbase:{:#x} -> pbase:{:#x})", vbase, pbase
                );
            }
        }

        let pd = self.get_pd_mut(pdpt_entry);
        let pd_idx = pd_index(vbase);
        let pd_entry = pd[pd_idx];
        drop(pd);

        // In case we can map something at a 2 MiB granularity and
        // we still have at least 2 MiB to map create large-page mappings
        if self.can_map_as_large_page(pdpt_entry, pbase, psize, vbase, rights) {
            return self.insert_large_mappings(
                pdpt_entry,
                vbase,
                pbase,
                psize,
                rights,
                insert_mapping,
            );
        } else if !pd_entry.is_present() {
            trace!(
                "Mapping 0x{:x} -- 0x{:x} is smaller than 2 MiB, going deeper.",
                vbase,
                vbase + psize
            );
            let pt = self.new_pt();
            let pd = self.get_pd_mut(pdpt_entry);
            pd[pd_idx] = pt;
        }

        let pd = self.get_pd_mut(pdpt_entry);
        assert!(
            pd[pd_idx].is_present(),
            "The PD entry we're relying on is not allocated?"
        );

        if pd[pd_idx].is_page() {
            if !insert_mapping {
                return Err(KError::AlreadyMapped { base: vbase });
            } else {
                panic!(
                    "An existing mapping already covers the 2 MiB range we're trying to map in?"
                );
            }
        }
        let pd_entry = pd[pd_idx];
        drop(pd);

        self.insert_base_mappings(pd_entry, vbase, pbase, psize, rights, insert_mapping)
    }

    /// Changes a mapping in the PageTable
    ///
    /// # Arguments
    ///  - `addr`: Identifies the mapping to be changed (can be anywhere in the mapped region)
    ///  - `action`: What action to perform: remove / update
    ///
    /// # Returns
    /// The affected virtual address region [`VAddr`, `VAddr` + usize), the underlying mapped
    /// physical address, and the old flags (or current flags if modify operation didn't change
    /// the flags).
    fn modify_generic<'a>(
        &'a mut self,
        addr: VAddr,
        action: Modify,
    ) -> Result<(VAddr, PAddr, usize, MapAction), KError> {
        let pml4_idx = pml4_index(addr);
        if self.pml4[pml4_idx].is_present() {
            let pdpt_idx = pdpt_index(addr);
            let pdpt = self.get_pdpt_mut(self.pml4[pml4_idx]);
            if pdpt[pdpt_idx].is_present() {
                if pdpt[pdpt_idx].is_page() {
                    // Page is a 1 GiB mapping, we have to return here
                    let vaddr_start = addr.align_down_to_huge_page();
                    let paddr_start = pdpt[pdpt_idx].address();
                    let old_flags: MapAction = pdpt[pdpt_idx].flags().into();
                    match action {
                        Modify::Unmap => {
                            pdpt[pdpt_idx] = PDPTEntry::new(PAddr::zero(), PDPTFlags::empty());
                        }
                        Modify::UpdateRights(new_rights) => {
                            let flags = PDPTFlags::P | PDPTFlags::PS | new_rights.to_pdpt_rights();
                            pdpt[pdpt_idx] = PDPTEntry::new(paddr_start, flags);
                        }
                    };
                    return Ok((vaddr_start, paddr_start, HUGE_PAGE_SIZE, old_flags));
                } else {
                    let pd_idx = pd_index(addr);
                    let pdpt_entry = pdpt[pdpt_idx];
                    drop(pdpt);
                    let pd = self.get_pd_mut(pdpt_entry);
                    if pd[pd_idx].is_present() {
                        if pd[pd_idx].is_page() {
                            // Encountered a 2 MiB mapping, we have to return here
                            let vaddr_start = addr.align_down_to_large_page();
                            let paddr_start = pd[pd_idx].address();
                            let old_flags: MapAction = pd[pd_idx].flags().into();
                            match action {
                                Modify::Unmap => {
                                    pd[pd_idx] = PDEntry::new(PAddr::zero(), PDFlags::empty());
                                }
                                Modify::UpdateRights(new_rights) => {
                                    let flags =
                                        PDFlags::P | PDFlags::PS | new_rights.to_pd_rights();
                                    pd[pd_idx] = PDEntry::new(paddr_start, flags);
                                }
                            };
                            return Ok((vaddr_start, paddr_start, LARGE_PAGE_SIZE, old_flags));
                        } else {
                            let pt_idx = pt_index(addr);
                            let pd_entry = pd[pd_idx];
                            drop(pd);
                            let pt = self.get_pt_mut(pd_entry);
                            if pt[pt_idx].is_present() {
                                // Encountered a 2 MiB mapping, we have to return here
                                let vaddr_start = addr.align_down_to_base_page();
                                let paddr_start = pt[pt_idx].address();
                                let old_flags: MapAction = pt[pt_idx].flags().into();
                                match action {
                                    Modify::Unmap => {
                                        pt[pt_idx] = PTEntry::new(PAddr::zero(), PTFlags::empty());
                                    }
                                    Modify::UpdateRights(new_rights) => {
                                        let flags = PTFlags::P | new_rights.to_pt_rights();
                                        pt[pt_idx] = PTEntry::new(paddr_start, flags);
                                    }
                                };
                                return Ok((vaddr_start, paddr_start, BASE_PAGE_SIZE, old_flags));
                            }
                        }
                    }
                }
            }
        }

        // else:
        Err(KError::NotMapped)
    }

    fn alloc_frame(&self) -> Frame {
        use core::alloc::Allocator;
        let frame_ptr = self.da.as_ref().map_or_else(
            || unsafe {
                let ptr = alloc::alloc::alloc(PT_LAYOUT);
                debug_assert!(!ptr.is_null());

                let nptr = NonNull::new_unchecked(ptr);
                NonNull::slice_from_raw_parts(nptr, PT_LAYOUT.size())
            },
            |da| da.allocate(PT_LAYOUT).unwrap(),
        );
        let vaddr = VAddr::from(frame_ptr.as_ptr() as *const u8 as u64);
        let paddr = crate::arch::memory::kernel_vaddr_to_paddr(vaddr);
        let mut frame = Frame::new(paddr, PT_LAYOUT.size(), 0);
        unsafe { frame.zero() };
        frame
    }

    fn new_pt(&self) -> PDEntry {
        let frame = self.alloc_frame();

        return PDEntry::new(frame.base, PDFlags::P | PDFlags::RW | PDFlags::US);
    }

    fn new_pd(&self) -> PDPTEntry {
        let frame = self.alloc_frame();
        return PDPTEntry::new(frame.base, PDPTFlags::P | PDPTFlags::RW | PDPTFlags::US);
    }

    fn new_pdpt(&self) -> PML4Entry {
        let frame = self.alloc_frame();
        return PML4Entry::new(frame.base, PML4Flags::P | PML4Flags::RW | PML4Flags::US);
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt(&self, entry: PDEntry) -> &PT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd(&self, entry: PDPTEntry) -> &PD {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt(&self, entry: PML4Entry) -> &PDPT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt_mut(&mut self, entry: PDEntry) -> &mut PT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd_mut(&mut self, entry: PDPTEntry) -> &mut PD {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt_mut(&mut self, entry: PML4Entry) -> &mut PDPT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }
}

pub(crate) struct ReadOnlyPageTable<'a> {
    pml4: &'a PML4,
}

impl<'a> ReadOnlyPageTable<'a> {
    /// Get read-only access to the current page-table.
    ///
    /// # Safety
    /// Be aware, pretty unsafe. We need to ensure that the current page-table
    /// is not modified or aliased mutably during the lifetime of this object.
    ///
    /// Generally only use this for debugging and sanity checking memory
    /// accesses for kernel GDB where it's clear we are in a state where won't
    /// make modification to PTs.
    ///
    /// Otherwise, access through NR/VSpace object is the way to go.
    ///
    /// # TODO
    /// We should have better type-safety for this to help with unsafety.
    /// Ideally using some token that is consumed on every page-table switch.
    pub unsafe fn current() -> Self {
        let cr3 = PAddr::from(x86::controlregs::cr3());
        assert_ne!(cr3, PAddr::zero());
        let pml4 = transmute::<VAddr, &PML4>(paddr_to_kernel_vaddr(cr3));
        ReadOnlyPageTable { pml4 }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt(&self, entry: PDEntry) -> &PT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd(&self, entry: PDPTEntry) -> &PD {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt(&self, entry: PML4Entry) -> &PDPT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }
}

impl<'a> AddressSpace for ReadOnlyPageTable<'a> {
    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), KError> {
        let pml4_idx = pml4_index(addr);
        if self.pml4[pml4_idx].is_present() {
            let pdpt_idx = pdpt_index(addr);
            let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
            if pdpt[pdpt_idx].is_present() {
                if pdpt[pdpt_idx].is_page() {
                    // Page is a 1 GiB mapping, we have to return here
                    let page_offset = addr.huge_page_offset();
                    let paddr = pdpt[pdpt_idx].address() + page_offset;
                    let flags: MapAction = pdpt[pdpt_idx].flags().into();
                    return Ok((paddr, flags));
                } else {
                    let pd_idx = pd_index(addr);
                    let pd = self.get_pd(pdpt[pdpt_idx]);
                    if pd[pd_idx].is_present() {
                        if pd[pd_idx].is_page() {
                            // Encountered a 2 MiB mapping, we have to return here
                            let page_offset = addr.large_page_offset();
                            let paddr = pd[pd_idx].address() + page_offset;
                            let flags: MapAction = pd[pd_idx].flags().into();
                            return Ok((paddr, flags));
                        } else {
                            let pt_idx = pt_index(addr);
                            let pt = self.get_pt(pd[pd_idx]);
                            if pt[pt_idx].is_present() {
                                let page_offset = addr.base_page_offset();
                                let paddr = pt[pt_idx].address() + page_offset;
                                let flags: MapAction = pt[pt_idx].flags().into();
                                return Ok((paddr, flags));
                            }
                        }
                    }
                }
            }
        }

        // else:
        Err(KError::NotMapped)
    }

    fn map_frame(&mut self, _base: VAddr, _frame: Frame, _action: MapAction) -> Result<(), KError> {
        Err(KError::NotSupported)
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        0
    }

    fn adjust(&mut self, _vaddr: VAddr, _rights: MapAction) -> Result<(VAddr, usize), KError> {
        Err(KError::NotSupported)
    }

    fn unmap(&mut self, _base: VAddr) -> Result<TlbFlushHandle, KError> {
        Err(KError::NotSupported)
    }
}
