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

macro_rules! is_page_aligned {
    ($num:expr) => {
        $num % BASE_PAGE_SIZE as u64 == 0
    };
}

/// UEFI memory region type for ELF data allocation.
pub const KernelElf: u32 = 0x80000001;

/// UEFI memory region type for kernel page-tables.
pub const KernelPT: u32 = 0x80000002;

/// UEFI memory region type for the kernel stack.
pub const KernelStack: u32 = 0x80000003;

/// UEFI memory region type for the memory map.
pub const UefiMemoryMap: u32 = 0x80000004;

/// UEFI memory region type for arguments passed to the kernel.
pub const KernelArgs: u32 = 0x80000005;

/// 512 GiB are that many bytes.
const GIB_512: usize = 512 * 512 * 512 * 0x1000;


/// Translate between PAddr and VAddr
///
/// TODO: this should really be called paddr_to_uefi_vaddr()!
pub(crate) fn paddr_to_kernel_vaddr(paddr: PAddr) -> VAddr {
    return VAddr::from(paddr.as_u64());
}

/// Mapping rights to give to address translation.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MapAction {
    /// Don't map
    None,
    /// Map region read-only.
    ReadUser,
    /// Map region read-only for kernel.
    ReadKernel,
    /// Map region read-write.
    ReadWriteUser,
    /// Map region read-write for kernel.
    ReadWriteKernel,
    /// Map region read-executable.
    ReadExecuteUser,
    /// Map region read-executable for kernel.
    ReadExecuteKernel,
    /// Map region read-write-executable.
    ReadWriteExecuteUser,
    /// Map region read-write-executable for kernel.
    ReadWriteExecuteKernel,
}

impl MapAction {
    /// Transform MapAction into rights for 1 GiB page.
    fn to_pdpt_rights(&self) -> PDPTFlags {
        use MapAction::*;
        match self {
            None => PDPTFlags::empty(),
            ReadUser => PDPTFlags::XD,
            ReadKernel => PDPTFlags::US | PDPTFlags::XD,
            ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD,
            ReadWriteKernel => PDPTFlags::RW | PDPTFlags::US | PDPTFlags::XD,
            ReadExecuteUser => PDPTFlags::empty(),
            ReadExecuteKernel => PDPTFlags::US,
            ReadWriteExecuteUser => PDPTFlags::RW,
            ReadWriteExecuteKernel => PDPTFlags::RW | PDPTFlags::US,
        }
    }

    /// Transform MapAction into rights for 2 MiB page.
    fn to_pd_rights(&self) -> PDFlags {
        use MapAction::*;
        match self {
            None => PDFlags::empty(),
            ReadUser => PDFlags::XD,
            ReadKernel => PDFlags::US | PDFlags::XD,
            ReadWriteUser => PDFlags::RW | PDFlags::XD,
            ReadWriteKernel => PDFlags::RW | PDFlags::US | PDFlags::XD,
            ReadExecuteUser => PDFlags::empty(),
            ReadExecuteKernel => PDFlags::US,
            ReadWriteExecuteUser => PDFlags::RW,
            ReadWriteExecuteKernel => PDFlags::RW | PDFlags::US,
        }
    }

    /// Transform MapAction into rights for 4KiB page.
    fn to_pt_rights(&self) -> PTFlags {
        use MapAction::*;
        match self {
            None => PTFlags::empty(),
            ReadUser => PTFlags::XD,
            ReadKernel => PTFlags::US | PTFlags::XD,
            ReadWriteUser => PTFlags::RW | PTFlags::XD,
            ReadWriteKernel => PTFlags::RW | PTFlags::US | PTFlags::XD,
            ReadExecuteUser => PTFlags::empty(),
            ReadExecuteKernel => PTFlags::US,
            ReadWriteExecuteUser => PTFlags::RW,
            ReadWriteExecuteKernel => PTFlags::RW | PTFlags::US,
        }
    }
}

impl fmt::Display for MapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use MapAction::*;
        match self {
            None => write!(f, " ---"),
            ReadUser => write!(f, "uR--"),
            ReadKernel => write!(f, "kR--"),
            ReadWriteUser => write!(f, "uRW-"),
            ReadWriteKernel => write!(f, "kRW-"),
            ReadExecuteUser => write!(f, "uR-X"),
            ReadExecuteKernel => write!(f, "kR-X"),
            ReadWriteExecuteUser => write!(f, "uRWX"),
            ReadWriteExecuteKernel => write!(f, "kRWX"),
        }
    }
}

/// A VSpace allows to create and modify a (virtual) address space.
pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
}

impl<'a> VSpace<'a> {
    /// Constructs an identity map but with an offset added to the region.
    ///
    /// # Example
    /// `map_identity_with_offset(0x20000, 0x1000, 0x2000, ReadWriteKernel)`
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
        while mapped < psize && pt_idx < 512 {
            if !pt[pt_idx].is_present() {
                pt[pt_idx] = PTEntry::new(pbase + mapped, PTFlags::P | rights.to_pt_rights());
                if rights.to_pt_rights() != PTFlags::RW {
                    trace!(
                        "Mapped 4KiB page: {:?} rights {:?}",
                        pt[pt_idx],
                        rights.to_pt_rights()
                    );
                }
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
        let paddr = VSpace::allocate_pages(actual_how_many, typ);
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
            unaligned_unused_pages_bottom + unaligned_unused_pages_top
                == actual_how_many - how_many,
            "Don't loose any pages"
        );

        // Free unused top and bottom regions again:
        unsafe {
            let st = system_table();
            st.as_ref()
                .boot_services()
                .free_pages(paddr.as_u64(), unaligned_unused_pages_bottom);
        }

        unsafe {
            let st = system_table();
            st.as_ref()
                .boot_services()
                .free_pages(aligned_end.as_u64(), unaligned_unused_pages_top);
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
    /// allocated physical memory (that got aligned to `palignment`).
    ///
    ///  * The base should be a multiple of `BASE_PAGE_SIZE`.
    ///  * The size should be a multiple of `BASE_PAGE_SIZE`.
    pub fn map(&mut self, base: VAddr, size: usize, rights: MapAction, palignment: u64) {
        assert_eq!(base % BASE_PAGE_SIZE, 0, "base is not page-aligned");
        assert_eq!(size % BASE_PAGE_SIZE, 0, "size is not page-aligned");
        let paddr = VSpace::allocate_pages_aligned(
            size / BASE_PAGE_SIZE,
            uefi::table::boot::MemoryType(KernelElf),
            palignment,
        );
        self.map_generic(base, (paddr, size), rights);
    }

    /// Fills a page in the virtual address space with the contents from region.
    pub(crate) fn fill(&self, address: VAddr, region: &[u8]) -> bool {
        assert_eq!(address % BASE_PAGE_SIZE, 0, "address is not page-aligned");
        assert!(region.len() <= BASE_PAGE_SIZE, "region too big to write.");

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

/// The starting address of the kernel address space
///
/// All physical mappings are identity mapped with KERNEL_OFFSET as
/// displacement.
pub const KERNEL_OFFSET: usize = 1 << 46;

/// This struct stores meta-data required to construct
/// an address space for the kernel and relocate the
/// kernel ELF binary into it.
///
/// It also implements the ElfLoader trait.
pub struct Kernel<'a> {
    pub offset: VAddr,
    pub mapping: Vec<(VAddr, usize, u64, MapAction)>,
    pub vspace: VSpace<'a>,
}

impl<'a> elfloader::ElfLoader for Kernel<'a> {
    /// Makes sure the process vspace is backed for the regions
    /// reported by the elf loader as loadable.
    ///
    /// Our strategy is to first figure out how much space we need,
    /// then allocate a single chunk of physical memory and
    /// map the individual pieces of it with different access rights.
    /// This has the advantage that our kernel address space is
    /// all a very simple 1:1 mapping of physical memory with the
    /// KERNEL_OFFSET added to it.
    ///
    /// For alignment the following should hold (I don't quite get
    /// what this parameter is useful for beyond the first load entry):
    /// base ≡ offset, modulo align_to. (Or rather, base % align = offset % align_to)
    fn allocate(&mut self, load_headers: elfloader::LoadableHeaders) -> Result<(), &'static str> {

        // Should contain what memory range we need to cover to contain
        // loadable regions:
        let mut min_base: VAddr = VAddr::from(usize::max_value());
        let mut max_end: VAddr = VAddr::from(0usize);
        let mut max_alignment: u64 = 0;

        for header in load_headers.into_iter() {
            let base = header.virtual_addr();
            let size = header.mem_size() as usize;
            let align_to = header.align();
            let flags = header.flags();

            // Calculate the offset and align to page boundaries
            // We can't expect to get something that is page-aligned from ELF
            let page_base: VAddr = VAddr::from(base & !0xfff); // Round down to nearest page-size
            let size_page = round_up!(size + (base & 0xfff) as usize, BASE_PAGE_SIZE as usize);
            assert!(size_page >= size);
            assert_eq!(size_page % BASE_PAGE_SIZE, 0);
            assert_eq!(page_base % BASE_PAGE_SIZE, 0);

            // Update virtual range for ELF file [max, min] and alignment:
            if max_alignment < align_to {
                max_alignment = align_to;
            }
            if min_base > page_base {
                min_base = page_base;
            }
            if page_base + size_page as u64 > max_end {
                max_end = page_base + size_page as u64;
            }

            debug!(
                "ELF Allocate: {:#x} -- {:#x} align to {:#x}",
                page_base,
                page_base + size_page,
                align_to
            );

            let map_action = match (flags.is_execute(), flags.is_write(), flags.is_read()) {
                (false, false, false) => MapAction::None,
                (true, false, false) => MapAction::None,
                (false, true, false) => MapAction::None,
                (false, false, true) => MapAction::ReadKernel,
                (true, false, true) => MapAction::ReadExecuteKernel,
                (true, true, false) => MapAction::None,
                (false, true, true) => MapAction::ReadWriteKernel,
                (true, true, true) => MapAction::ReadWriteExecuteKernel,
            };

            // We don't allocate yet -- just record the allocation parameters
            // This has the advantage that we know how much memory we need
            // and can reserve one consecutive chunk of physical memory
            self.mapping
                .push((page_base, size_page, align_to, map_action));
        }
        assert!(
            is_page_aligned!(min_base),
            "min base is not aligned to page-size"
        );
        assert!(
            is_page_aligned!(max_end),
            "max end is not aligned to page-size"
        );
        let pbase = VSpace::allocate_pages_aligned(
            (max_end - min_base) >> BASE_PAGE_SHIFT,
            uefi::table::boot::MemoryType(KernelElf),
            max_alignment,
        );

        self.offset = VAddr::from(KERNEL_OFFSET + pbase.as_usize());
        info!("Kernel loaded at address: {:#x}", self.offset);

        // Do the mappings:
        for (base, size, _alignment, action) in self.mapping.iter() {
            self.vspace
                .map_generic(self.offset + *base, (pbase + base.as_u64(), *size), *action);
        }

        Ok(())
    }

    /// Load a region of bytes into the virtual address space of the process.
    fn load(&mut self, destination: u64, region: &[u8]) -> Result<(), &'static str> {
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
    fn relocate(&mut self, entry: &elfloader::Rela<elfloader::P64>) -> Result<(), &'static str> {
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

    fn make_readonly(&mut self, base: u64, size: usize) -> Result<(), &'static str> {
        trace!(
            "Make readonly {:#x} -- {:#x}",
            self.offset + base,
            self.offset + base + size
        );
        assert_eq!(
            (self.offset + base + size) % BASE_PAGE_SIZE,
            0,
            "RELRO segment doesn't end on a page-boundary"
        );

        let from: VAddr = self.offset + (base & !0xfff); // Round down to nearest page-size
        let to = self.offset + base + size;

        // TODO: NYI
        // self.vspace.change_rights(from, to, MapAction::ReadKernel);

        Ok(())
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
