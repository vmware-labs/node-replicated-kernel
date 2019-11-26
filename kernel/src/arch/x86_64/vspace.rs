use core::mem::transmute;
use core::pin::Pin;

use alloc::boxed::Box;

use x86::bits64::paging::*;

use crate::memory::vspace::*;
use crate::memory::{
    kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, Frame, PAddr, PhysicalPageProvider, VAddr,
};

pub struct VSpace {
    pub pml4: Pin<Box<PML4>>,
}

impl AddressSpace for VSpace {
    fn map_frame(
        &mut self,
        base: VAddr,
        frame: Frame,
        action: MapAction,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        if frame.size() == 0 {
            return Err(AddressSpaceError::InvalidFrame);
        }

        // This will check that the current region doesn't overlap
        // with an already mapped one (and return AddressSpaceError if so)
        // TODO(performance): This can be done faster (rather than trying
        // to map with a None action)
        self.map_generic(base, (frame.base, frame.size()), MapAction::None, pager)?;

        self.map_generic(base, (frame.base, frame.size()), action, pager)
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        20
    }

    fn adjust(
        &mut self,
        _base: VAddr,
        _length: usize,
        _rights: MapAction,
    ) -> Result<usize, AddressSpaceError> {
        Ok(0)
    }

    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError> {
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
        Err(AddressSpaceError::NotMapped)
    }

    fn unmap(&mut self, _base: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError> {
        //Ok((Default::default(), Frame::empty()))
        Err(AddressSpaceError::NotMapped)
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        //panic!("Drop for VSpace!");
    }
}

impl VSpace {
    /// Create a new address-space.
    ///
    /// Allocate an initial PML4 table for it.
    pub fn new() -> VSpace {
        VSpace {
            pml4: Box::pin(
                [PML4Entry::new(PAddr::from(0x0u64), PML4Flags::empty()); PAGE_SIZE_ENTRIES],
            ),
        }
    }

    pub fn pml4_address(&self) -> PAddr {
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
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
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

        self.map_generic(vbase, (pbase, size), rights, pager)
    }

    /// Identity maps a given physical memory range [`base`, `base` + `size`]
    /// in the address space.
    pub(crate) fn map_identity(
        &mut self,
        base: PAddr,
        size: usize,
        rights: MapAction,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        self.map_identity_with_offset(PAddr::from(0x0), base, size, rights, pager)
    }

    /// Retrieves the relevant PDPT table for a given virtual address `vbase`.
    ///
    /// Allocates the PDPT page if it doesn't exist yet.
    fn get_or_alloc_pdpt(
        &mut self,
        vbase: VAddr,
        pager: &mut dyn PhysicalPageProvider,
    ) -> &mut PDPT {
        let pml4_idx = pml4_index(vbase);
        if !self.pml4[pml4_idx].is_present() {
            trace!("Need new PDPDT for {:?} @ PML4[{}]", vbase, pml4_idx);
            self.pml4[pml4_idx] = VSpace::new_pdpt(pager);
        }
        assert!(
            self.pml4[pml4_idx].is_present(),
            "The PML4 slot we need was not allocated?"
        );

        self.get_pdpt_mut(self.pml4[pml4_idx])
    }

    /// Check if we can just insert a huge page for the current mapping
    fn can_map_as_huge_page(pbase: PAddr, psize: usize, pos_in_pt: VAddr, vbase: VAddr) -> bool {
        let want_to_map_here = vbase == pos_in_pt;
        let physical_frame_is_aligned = pbase % HUGE_PAGE_SIZE == 0;
        let want_to_map_at_least_1gib = psize >= HUGE_PAGE_SIZE;

        want_to_map_here && physical_frame_is_aligned && want_to_map_at_least_1gib
    }

    /// Check if we can just insert a huge page for the current mapping
    fn can_map_as_large_page(pbase: PAddr, psize: usize, pos_in_pt: VAddr, vbase: VAddr) -> bool {
        let want_to_map_here = vbase == pos_in_pt;
        let physical_frame_is_aligned = pbase % LARGE_PAGE_SIZE == 0;
        let want_to_map_at_least_2mib = psize >= LARGE_PAGE_SIZE;

        want_to_map_here && physical_frame_is_aligned && want_to_map_at_least_2mib
    }

    /// Starts to insert huge-pages for `vbase` at the given `pdpt_idx`.
    fn insert_huge_mappings(
        &mut self,
        mut pdpt_idx: usize,
        vbase: VAddr,
        pbase: PAddr,
        psize: usize,
        rights: MapAction,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        let pdpt = self.get_or_alloc_pdpt(vbase, pager);

        // To track how much space we've mapped so far
        let mut mapped = 0;

        // Add entries to PDPT as long as we're within this allocated PDPT table
        // and have 1 GiB chunks to map:
        while mapped < psize && ((psize - mapped) >= HUGE_PAGE_SIZE) && pdpt_idx < pdpt.len() {
            if let MapAction::None = rights {
                // Check if we could map in theory (no overlap)
                if pdpt[pdpt_idx].is_present() {
                    let address = pdpt[pdpt_idx].address();
                    let cur_rights: MapAction = pdpt[pdpt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        // Return an error if a frame is present,
                        // and it's not exactly the frame+rights combo we're
                        // trying to map anyways
                        return Err(AddressSpaceError::AlreadyMapped);
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
                pager,
            );
        }
    }

    /// Starts to insert large-pages for `vbase` at the given `pd_idx`.
    fn insert_large_mappings(
        &mut self,
        pdpt_entry: PDPTEntry,
        mut pd_idx: usize,
        vbase: VAddr,
        pbase: PAddr,
        psize: usize,
        rights: MapAction,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        let pd = self.get_pd_mut(pdpt_entry);

        // To track how much space we've mapped so far
        let mut mapped = 0;

        // Add entries as long as we are within this allocated PDPT table
        // and have at least 2 MiB things to map
        while mapped < psize && ((psize - mapped) >= LARGE_PAGE_SIZE) && pd_idx < pd.len() {
            if let MapAction::None = rights {
                // Check if we could map in theory (no overlap)
                if pd[pd_idx].is_present() {
                    let address = pd[pd_idx].address();
                    let cur_rights: MapAction = pd[pd_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        // Return an error if a frame is present,
                        // and it's not exactly the frame+rights combo we're
                        // trying to map anyways
                        return Err(AddressSpaceError::AlreadyMapped);
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
                pager,
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
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        let pt = self.get_pt_mut(pd_entry);
        let mut pt_idx = pt_index(vbase);

        // To track how much space we've mapped so far
        let mut mapped: usize = 0;

        while mapped < psize && pt_idx < pt.len() {
            if let MapAction::None = rights {
                // Check if we could map in theory (no overlap)
                if pt[pt_idx].is_present() {
                    let address = pt[pt_idx].address();
                    let cur_rights: MapAction = pt[pt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        // Return an error if a frame is present,
                        // and it's not exactly the frame+rights combo we're
                        // trying to map anyways
                        return Err(AddressSpaceError::AlreadyMapped);
                    }
                }
            } else {
                if pt[pt_idx].is_present() {
                    let address = pt[pt_idx].address();
                    let cur_rights: MapAction = pt[pt_idx].flags().into();
                    if address != pbase + mapped || cur_rights != rights {
                        panic!("Trying to map 4 KiB page but it conflicts with existing mapping");
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
                pager,
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
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        let (pbase, psize) = pregion;
        assert_eq!(pbase % BASE_PAGE_SIZE, 0);
        assert_eq!(psize % BASE_PAGE_SIZE, 0);
        assert_eq!(vbase % BASE_PAGE_SIZE, 0);

        debug!(
            "map_generic {:#x} -- {:#x} -> {:#x} -- {:#x} {}",
            vbase,
            vbase + psize,
            pbase,
            pbase + psize,
            rights
        );

        let pml4_idx = pml4_index(vbase);
        let pdpt = self.get_or_alloc_pdpt(vbase, pager);
        let pdpt_idx = pdpt_index(vbase);

        if !pdpt[pdpt_idx].is_present() {
            // The virtual address corresponding to our position within the page-table
            let vaddr_pos = VAddr::from(PML4_SLOT_SIZE * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx);
            if VSpace::can_map_as_huge_page(pbase, psize, vaddr_pos, vbase) {
                drop(pdpt);
                // Start inserting mappings here in case we can map something as 1 GiB pages
                return self.insert_huge_mappings(pdpt_idx, vbase, pbase, psize, rights, pager);
            } else {
                trace!(
                    "Mapping 0x{:x} -- 0x{:x} is smaller than 1 GiB, going deeper.",
                    vbase,
                    vbase + psize
                );
                pdpt[pdpt_idx] = VSpace::new_pd(pager);
            }
        }
        assert!(
            pdpt[pdpt_idx].is_present(),
            "The PDPT entry we're relying on is not allocated?"
        );

        if pdpt[pdpt_idx].is_page() {
            if let MapAction::None = rights {
                // Check if we could map in theory (no overlap)
                return Err(AddressSpaceError::AlreadyMapped);
            } else {
                panic!(
                    "An existing mapping already covers the 1 GiB range we're trying to map in?"
                );
            }
        }
        let pdpt_entry = pdpt[pdpt_idx];
        drop(pdpt); // Makes sure we can borrow pd

        let pd = self.get_pd_mut(pdpt_entry);
        let pd_idx = pd_index(vbase);
        if !pd[pd_idx].is_present() {
            // The virtual address corresponding to our position within the page-table
            let vaddr_pos: VAddr = VAddr::from(
                PML4_SLOT_SIZE * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx + LARGE_PAGE_SIZE * pd_idx,
            );
            // In case we can map something at a 2 MiB granularity and
            // we still have at least 2 MiB to map create large-page mappings
            if VSpace::can_map_as_large_page(pbase, psize, vaddr_pos, vbase) {
                drop(pd);
                return self
                    .insert_large_mappings(pdpt_entry, pd_idx, vbase, pbase, psize, rights, pager);
            } else {
                trace!(
                    "Mapping 0x{:x} -- 0x{:x} is smaller than 2 MiB, going deeper.",
                    vbase,
                    vbase + psize
                );
                pd[pd_idx] = VSpace::new_pt(pager);
            }
        }
        assert!(
            pd[pd_idx].is_present(),
            "The PD entry we're relying on is not allocated?"
        );

        if pd[pd_idx].is_page() {
            if let MapAction::None = rights {
                // Check if we could map in theory (no overlap)
                return Err(AddressSpaceError::AlreadyMapped);
            } else {
                panic!(
                    "An existing mapping already covers the 2 MiB range we're trying to map in?"
                );
            }
        }
        let pd_entry = pd[pd_idx];
        drop(pd);

        self.insert_base_mappings(pd_entry, vbase, pbase, psize, rights, pager)
    }

    fn new_pt(pager: &mut dyn crate::memory::PhysicalPageProvider) -> PDEntry {
        let mut frame: Frame = pager.allocate_base_page().expect("Allocation must work");
        unsafe { frame.zero() };
        return PDEntry::new(frame.base, PDFlags::P | PDFlags::RW | PDFlags::US);
    }

    fn new_pd(pager: &mut dyn crate::memory::PhysicalPageProvider) -> PDPTEntry {
        let mut frame: Frame = pager.allocate_base_page().expect("Allocation must work");
        unsafe { frame.zero() };
        return PDPTEntry::new(frame.base, PDPTFlags::P | PDPTFlags::RW | PDPTFlags::US);
    }

    fn new_pdpt(pager: &mut dyn crate::memory::PhysicalPageProvider) -> PML4Entry {
        let mut frame: Frame = pager.allocate_base_page().expect("Allocation must work");
        unsafe { frame.zero() };
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

#[cfg(test)]
mod test {
    use core::cmp::{Eq, PartialEq};
    use core::ptr;

    use proptest::prelude::*;

    use super::*;
    use crate::*;

    use crate::memory::tcache::TCache;
    use crate::memory::vspace::model::ModelAddressSpace;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestAction {
        Map(VAddr, Frame, MapAction),
        Adjust(VAddr, usize, MapAction),
        Resolve(VAddr),
        Unmap(VAddr),
    }

    fn action() -> impl Strategy<Value = TestAction> {
        prop_oneof![
            (
                vaddrs(0x60_0000),
                frames(0x60_0000, 0x40_0000),
                map_rights()
            )
                .prop_map(|(a, b, c)| TestAction::Map(a, b, c)),
            //(vaddrs(0x60_0000), any::<usize>(), map_rights())
            //    .prop_map(|(a, b, c)| TestAction::Adjust(a, b, c)),
            //vaddrs(0x60_0000).prop_map(TestAction::Unmap),
            vaddrs(0x60_0000).prop_map(TestAction::Resolve),
        ]
    }

    fn actions() -> impl Strategy<Value = Vec<TestAction>> {
        prop::collection::vec(action(), 0..512)
    }

    prop_compose! {
        fn frames(max_base: u64, max_size: usize)(base in base_pages(max_base), size in 0..max_size) -> Frame {
            Frame::new(PAddr::from(base), size & !0xfff, 0)
        }
    }
    prop_compose! {
        fn vaddrs(max: u64)(base in 0..max) -> VAddr { VAddr::from(base & !0xfff) }
    }

    prop_compose! {
        fn base_pages(max: u64)(base in 0..max) -> u64 { base & !0xfff }
    }

    prop_compose! {
        fn large_pages(max: u64)(base in 0..max) -> u64 { base & !0x1fffff }
    }

    fn map_rights() -> impl Strategy<Value = MapAction> {
        prop_oneof![
            //Just(MapAction::None),
            Just(MapAction::ReadUser),
            Just(MapAction::ReadKernel),
            Just(MapAction::ReadWriteUser),
            Just(MapAction::ReadWriteKernel),
            Just(MapAction::ReadExecuteUser),
            Just(MapAction::ReadExecuteKernel),
            Just(MapAction::ReadWriteExecuteUser),
            Just(MapAction::ReadWriteExecuteKernel),
        ]
    }

    prop_compose! {
        fn do_action()(action in action(),
                       base in base_pages(0x600000),
                       frame in frames(0x600000, 0x400000),
                       length in 0..(10*4096usize),
                       rights in map_rights()) -> (TestAction, VAddr, Frame, usize, MapAction)
        {
            (action, VAddr::from(base), frame, length, rights)
        }
    }

    proptest! {
        /// Verify that our implementation behaves according to the `ModelAddressSpace`.
        #[test]
        fn model_equivalence(ops in actions()) {
            //let _r = env_logger::try_init();
            //trace!("doing ops = {:?}", ops);
            use TestAction::*;
            let mut mm = crate::arch::memory::MemoryMapper::new();
            let f = mm.allocate_frame(16 * 1024 * 1024).unwrap();
            let mut tcache = TCache::new_with_frame(0, 0, f);

            let mut totest = VSpace::new();
            let mut model: ModelAddressSpace = Default::default();

            for action in ops {
                //trace!("execute action {:?}", action);
                match action {
                    Map(base, frame, rights) => {
                        let rmodel = model.map_frame(base, frame, rights, &mut tcache);
                        let rtotest = totest.map_frame(base, frame, rights, &mut tcache);
                        assert_eq!(rmodel, rtotest);
                    }
                    Adjust(base, len, rights) => {
                        let rmodel = model.adjust(base, len, rights);
                        let rtotest = totest.adjust(base, len, rights);
                        assert_eq!(rmodel, rtotest);
                    }
                    Resolve(base) => {
                        let rmodel = model.resolve(base);
                        let rtotest = totest.resolve(base);
                        assert_eq!(rmodel, rtotest);
                    }
                    Unmap(base) => {
                        let rmodel = model.unmap(base);
                        let rtotest = totest.unmap(base);
                        assert_eq!(rmodel, rtotest);
                    }
                }
            }
        }
    }
}
