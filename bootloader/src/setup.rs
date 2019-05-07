use crate::alloc::vec::Vec;

use core::fmt;
use core::mem::transmute;

use elfloader;
use uefi::table::boot::AllocateType;
use uefi_services::system_table;
use x86::bits64::paging::*;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

pub(crate) fn paddr_to_kernel_vaddr(paddr: PAddr) -> VAddr {
    return VAddr::from(paddr.as_u64());
}

/// Mapping rights to give to address translation.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MapAction {
    /// No access (but allocated and mapped).
    None,
    /// Map region read-only.
    Read,
    /// Map region read-write.
    ReadWrite,
    /// Map region read-executable.
    ReadExecute,
    /// Map region read-write-executable.
    ReadWriteExecute,
}

impl fmt::Display for MapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use MapAction::*;
        match self {
            None => write!(f, "---"),
            Read => write!(f, "R--"),
            ReadWrite => write!(f, "RW-"),
            ReadExecute => write!(f, "R-X"),
            ReadWriteExecute => write!(f, "RWX"),
        }
    }
}


pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
}

const GIB_512: usize = 512 * 512 * 512 * 0x1000;

impl<'a> VSpace<'a> {
    /// Constructs an identity map but with an offset added to the region.
    ///
    /// # Example
    /// `map_identity_with_offset(0x20000, 0x1000, 0x2000, ReadWrite)`
    /// will set the virtual addresses at 0x21000 -- 0x22000 to
    /// point to physical 0x1000 - 0x2000.
    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: PAddr,
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
    /// We require that `vbase` and `pregion` values are all aligned to page-size.
    /// TODO: We panic in case there is already a mapping covering the region (should return error).
    /// TODO: `rights` MapAction is currently ignored, everything is mapped RWX.
    pub(crate) fn map_generic(&mut self, vbase: VAddr, pregion: (PAddr, usize), rights: MapAction) {
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
                        PDPTFlags::P | PDPTFlags::RW | PDPTFlags::PS,
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
                    pd[pd_idx] =
                        PDEntry::new(pbase + mapped, PDFlags::P | PDFlags::RW | PDFlags::PS);
                    debug!(
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
        while mapped < psize && pt_idx < 512 {
            if !pt[pt_idx].is_present() {
                pt[pt_idx] = PTEntry::new(pbase + mapped, PTFlags::P | PTFlags::RW);
                trace!("Mapped 4KiB page: {:?}", pt[pt_idx]);
            } else {
                assert!(
                    pt[pt_idx].is_present(),
                    "An existing mapping already covers the 4 KiB range we're trying to map?"
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

    /// A simple wrapper function for allocating just oen page.
    pub(crate) fn allocate_one_page() -> PAddr {
        VSpace::allocate_pages(1, uefi::table::boot::MemoryType(KernelPT))
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
                    st.as_ref().boot_services().memset(
                        num.unwrap() as *mut u8,
                        how_many * BASE_PAGE_SIZE,
                        0u8,
                    );
                    PAddr::from(num.unwrap())
                }
                Err(status) => panic!("failed to allocate {:?}", status),
            }
        }
    }

    fn new_page(&mut self) -> PTEntry {
        let paddr: PAddr = VSpace::allocate_one_page();
        return PTEntry::new(paddr, PTFlags::P | PTFlags::RW);
    }

    fn new_pt(&mut self) -> PDEntry {
        let paddr: PAddr = VSpace::allocate_one_page();
        return PDEntry::new(paddr, PDFlags::P | PDFlags::RW);
    }

    fn new_pd(&mut self) -> PDPTEntry {
        let paddr: PAddr = VSpace::allocate_one_page();
        return PDPTEntry::new(paddr, PDPTFlags::P | PDPTFlags::RW);
    }

    fn new_pdpt(&mut self) -> PML4Entry {
        let paddr: PAddr = VSpace::allocate_one_page();
        return PML4Entry::new(paddr, PML4Flags::P | PML4Flags::RW);
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt<'b>(&self, entry: PDEntry) -> &'b mut PT {
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd<'b>(&self, entry: PDPTEntry) -> &'b mut PD {
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut PDPT {
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    pub(crate) fn resolve_addr(&self, addr: VAddr) -> Option<PAddr> {
        let pml4_idx = pml4_index(addr);
        if self.pml4[pml4_idx].is_present() {
            let pdpt_idx = pdpt_index(addr);
            let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
            if pdpt[pdpt_idx].is_present() {
                if pdpt[pdpt_idx].is_page() {
                    // Page is a 1 GiB mapping, we have to return here
                    let page_offset: usize = addr & 0x3fffffff;
                    return Some(pdpt[pdpt_idx].address() + page_offset);
                } else {
                    let pd_idx = pd_index(addr);
                    let pd = self.get_pd(pdpt[pdpt_idx]);
                    if pd[pd_idx].is_present() {
                        if pd[pd_idx].is_page() {
                            // Encountered a 2 MiB mapping, we have to return here
                            let page_offset: usize = addr & 0x1fffff;
                            return Some(pd[pd_idx].address() + page_offset);
                        } else {
                            let pt_idx = pt_index(addr);
                            let pt = self.get_pt(pd[pd_idx]);
                            if pt[pt_idx].is_present() {
                                let page_offset: usize = addr & 0xfff;
                                return Some(pt[pt_idx].address() + page_offset);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Resolve an address of a virtual (base) page in the address space and return
    /// a slice of the corresponding physical memory region of it.
    ///
    /// # Safety
    ///  * It's only safe to access this region if it is actually mapped.
    unsafe fn resolve_to_page(&self, base: VAddr) -> Option<&mut [u8; BASE_PAGE_SIZE]> {
        self.resolve_addr(base).map(|paddr| {
            let kernel_addr = paddr_to_kernel_vaddr(paddr);
            unsafe { transmute::<VAddr, &mut [u8; BASE_PAGE_SIZE as usize]>(kernel_addr) }
        })
    }

    /// Back a region of virtual address space with
    /// allocated physical memory.
    ///
    ///  * The base should be a multiple of `BASE_PAGE_SIZE`.
    ///  * The size should be a multiple of `BASE_PAGE_SIZE`.
    pub fn map(&mut self, base: VAddr, size: usize, rights: MapAction) {
        assert_eq!(base % BASE_PAGE_SIZE, 0, "base is not page-aligned");
        assert_eq!(size % BASE_PAGE_SIZE, 0, "size is not page-aligned");
        let paddr = VSpace::allocate_pages(
            size / BASE_PAGE_SIZE,
            uefi::table::boot::MemoryType(KernelElf),
        );
        self.map_generic(base, (paddr, size), rights);
    }

    /// Fills a page in the virtual address space with the contents from region.
    pub(crate) fn fill(&self, address: VAddr, region: &[u8]) -> bool {
        assert_eq!(address % BASE_PAGE_SIZE, 0, "address is not page-aligned");
        assert!(region.len() <= BASE_PAGE_SIZE, "Region too big to write.");

        unsafe {
            match self.resolve_to_page(address) {
                Some(page) => {
                    for (idx, b) in region.iter().enumerate() {
                        page[idx] = *b;
                    }
                    true
                }
                None => {
                    error!("Unable to resolve vaddr {:#x} to physical page.", address);
                    false
                }
            }
        }
    }
}

pub const KernelElf: u32 = 0x80000001;
pub const KernelPT: u32 = 0x80000002;
pub const KernelStack: u32 = 0x80000003;
pub const UefiMemoryMap: u32 = 0x80000004;
pub const KernelArgs: u32 = 0x80000005;

pub const KERNEL_OFFSET: usize = 1 << 46;

pub struct Kernel<'a> {
    pub allocated: bool,
    pub offset: VAddr,
    pub mapping: Vec<(VAddr, usize)>,
    pub vspace: VSpace<'a>,
}

impl<'a> elfloader::ElfLoader for Kernel<'a> {

    /// Makes sure the process vspace is backed for the region reported by the elf loader.
    fn allocate(
        &mut self,
        base: u64,
        size: usize,
        _flags: elfloader::Flags,
    ) -> Result<(), &'static str> {
        // Calculate the offset and align to page boundaries
        // We can't expect to get something that is page-aligned from ELF
        let page_base: VAddr = self.offset + (base & !0xfff); // Round down to nearest page-size
        let size_page = round_up!(size + (base & 0xfff) as usize, BASE_PAGE_SIZE as usize);
        assert!(size_page >= size);
        assert_eq!(size_page % BASE_PAGE_SIZE, 0);
        assert!(page_base >= VAddr::from(base));
        assert_eq!(page_base % BASE_PAGE_SIZE, 0);

        debug!(
            "ELF Allocate: {:#x} -- {:#x}",
            page_base,
            page_base + size_page,
        );

        self.mapping.push((page_base, size_page));
        /*self.vspace
            .map(page_base, size_page, MapAction::ReadWriteExecute);
        self.allocated = true;*/
        Ok(())
    }
    /*
    DEBUG: ELF Allocate: 0x400000000000 -- 0x4000000ba000
    DEBUG: ELF Allocate: 0x4000002ba000 -- 0x4000002c4000
    INFO: load dynamic segement ProgramHeader64 { type_: Ok(Dynamic), flags: Flags(6), offset: 790224, virtual_addr: 2887376, physical_addr: 2887376, file_size
    : 304, mem_size: 304, align: 8 }
    ERROR: DO ALLOCS NOW!~! 0x400000000000 0x4000002c4000
    DEBUG: map_generic 0x400000000000 -- 0x4000002c4000 -> 0x3ddce000 -- 0x3e092000 RWX
    DEBUG: map_generic 0x400000200000 -- 0x4000002c4000 -> 0x3dfce000 -- 0x3e092000 RWX
    DEBUG: ELF Load at 0x400000000000 -- 0x4000000b95e0
    DEBUG: ELF Load at 0x4000002ba1d0 -- 0x4000002c13c0


    DEBUG: ELF Allocate: 0x400000000000 -- 0x4000000ba000
    DEBUG: map_generic 0x400000000000 -- 0x4000000ba000 -> 0x3dfd8000 -- 0x3e092000 RWX
    DEBUG: ELF Allocate: 0x4000002ba000 -- 0x4000002c4000
    DEBUG: map_generic 0x4000002ba000 -- 0x4000002c4000 -> 0x3dfcb000 -- 0x3dfd5000 RWX
        */

    /// Load a region of bytes into the virtual address space of the process.
    fn load(&mut self, destination: u64, region: &[u8]) -> Result<(), &'static str> {
        if !self.allocated {
            let mut min_base: VAddr = VAddr::from(usize::max_value());
            let mut max_end: VAddr = VAddr::from(0usize);
            for (base, size) in self.mapping.iter() {
                if min_base > *base {
                    min_base = *base;
                }

                if *base + *size > max_end {
                    max_end = *base + *size;
                }
            }

            error!("DO ALLOCS NOW!~! {:#x} {:#x}", min_base, max_end);
            assert_eq!(
                min_base % BASE_PAGE_SIZE,
                0,
                "min base is not aligned to page-size"
            );
            assert_eq!(
                max_end % BASE_PAGE_SIZE,
                0,
                "max end is not aligned to page-size"
            );
            let pbase = VSpace::allocate_pages(
                (max_end - min_base).as_usize() / BASE_PAGE_SIZE,
                uefi::table::boot::MemoryType(KernelElf),
            );

            self.vspace.map_generic(
                self.offset,
                (pbase, (max_end - min_base).as_usize()),
                MapAction::ReadWriteExecute,
            );

            self.allocated = true;
        }

        let destination = self.offset + destination;
        debug!(
            "ELF Load at {:#x} -- {:#x}",
            destination,
            destination + region.len()
        );

        // Load the region at destination in the kernel space
        for (idx, val) in region.iter().enumerate() {
            let vaddr = VAddr::from(destination + idx);
            let paddr = self.vspace.resolve_addr(vaddr);
            if paddr.is_some() {
                // Inefficient byte-wise copy since we don't necessarily
                // have consecutive "physical" memory in UEFI we can
                // just memcopy this stuff into.
                // Best way would probably mean to map replicate the kernel mappings
                // in UEFI space if this ever becomes a problem.
                let ptr = paddr.unwrap().as_u64() as *mut u8;
                unsafe {
                    *ptr = *val;
                }
            } else {
                return Err("Can't write to the resolved address in the kernel vspace.");
            }
        }

        Ok(())
    }

    /// Relocating the kernel symbols.
    ///
    /// Since the kernel is a position independent executable that is 'statically' linked
    /// with all dependencies we only expect to get relocations of type RELATIVE.
    /// Otherwise, the build would be broken or you got a garbage ELF file.
    /// We return an error in this case.
    fn relocate(
        &mut self,
        entry: &elfloader::Rela<elfloader::P64>,
        header_base: u64,
    ) -> Result<(), &'static str> {
        // TODO: we can't relocate below our header base in an ELF binary
        // not impossible but not really needed
        assert!(self.offset.as_u64() >= header_base);

        // Get the pointer to where the relocation happens in the
        // memory where we loaded the headers
        // The forumla for this is our offset where the kernel is starting,
        // plus the offset of the entry to jump to the code piece
        let addr = (self.offset.as_u64() + entry.get_offset());

        // We can't access addr in UEFI space so we resolve it to a physical address (UEFI has 1:1 mappings)
        let uefi_addr = self
            .vspace
            .resolve_addr(VAddr::from(addr))
            .expect("Can't resolve address")
            .as_u64() as *mut u64;

        use elfloader::TypeRela64;
        if let TypeRela64::R_RELATIVE = TypeRela64::from(entry.get_type()) {
            // This is a relative relocation of a 64 bit value, we add the offset (where we put our
            // binary in the vspace) to the addend and we're done:
            unsafe {
                // Scary unsafe changing stuff in random memory locations based on
                // ELF binary values weee!
                *uefi_addr = self.offset.as_u64() + entry.get_addend();
            }
            Ok(())
        } else {
            Err("Can only handle R_RELATIVE for relocation")
        }
    }
}

pub unsafe fn dump_table(pml4_table: &PML4) {
    for (pml_idx, pml_item) in pml4_table.iter().enumerate() {
        if pml_item.is_present() {
            let pdpt_table = unsafe {
                transmute::<VAddr, &mut PDPT>(VAddr::from_u64(pml_item.address().as_u64()))
            };

            for (pdpt_idx, pdpt_item) in pdpt_table.iter().enumerate() {
                if pdpt_item.is_present() {
                    let pd_table = unsafe {
                        transmute::<VAddr, &mut PD>(VAddr::from_u64(pdpt_item.address().as_u64()))
                    };
                    if pdpt_item.is_page() {
                        let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                            + (512 * (512 * 0x1000)) * pdpt_idx;

                        info!("PDPT item: vaddr 0x{:x} maps to {:?}", vaddr, pdpt_item);
                    } else {
                        for (pd_idx, pd_item) in pd_table.iter().enumerate() {
                            if pd_item.is_present() {
                                let ptes = unsafe {
                                    transmute::<VAddr, &mut PT>(VAddr::from_u64(
                                        pd_item.address().as_u64(),
                                    ))
                                };

                                if pd_item.is_page() {
                                    let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                                        + (512 * (512 * 0x1000)) * pdpt_idx
                                        + (512 * 0x1000) * pd_idx;

                                    info!("PD item: vaddr 0x{:x} maps to {:?}", vaddr, pd_item);
                                } else {
                                    assert!(!pd_item.is_page());
                                    for (pte_idx, pte) in ptes.iter().enumerate() {
                                        let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
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
