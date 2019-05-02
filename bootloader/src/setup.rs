use crate::alloc::vec::Vec;

use core::mem::transmute;

use elfloader::elf;
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


pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
}

const GIB_512: usize = 512 * 512 * 512 * 0x1000;

impl<'a> VSpace<'a> {
    pub(crate) fn map_identity(&mut self, base: VAddr, end: VAddr) {
        let size: usize = (end - base).into();
        debug!("map_identity 0x{:x} -- 0x{:x}", base, end);

        let pml4_idx = pml4_index(base);
        //info!("map base {:x} to pml4 {:p} @ pml4_idx {}", base, self.pml4, pml4_idx);
        if !self.pml4[pml4_idx].is_present() {
            self.pml4[pml4_idx] = self.new_pdpt();
        }
        assert!(self.pml4[pml4_idx].is_present());

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let mut pdpt_idx = pdpt_index(base);
        if !pdpt[pdpt_idx].is_present() {
            let vaddr_pos: usize = GIB_512 * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx;

            // In case we can map something at a 1 GiB granularity and
            // we still have at least 1 GiB to map create huge page mappings
            if base.as_usize() == vaddr_pos && size > HUGE_PAGE_SIZE {
                let mut mapped = 0;
                // Add entries as long as we are within this allocated PDPT table
                // and have at least 1 GiB things to map
                while mapped < size && ((size - mapped) > HUGE_PAGE_SIZE) && pdpt_idx < 512 {
                    let paddr: PAddr = PAddr::from_u64((base + mapped).as_u64());
                    pdpt[pdpt_idx] =
                        PDPTEntry::new(paddr, PDPTFlags::P | PDPTFlags::RW | PDPTFlags::PS);
                    debug!(
                        "Mapping 1GiB range 0x{:x} -- 0x{:x}",
                        base + mapped,
                        (base + mapped) + HUGE_PAGE_SIZE
                    );

                    pdpt_idx += 1;
                    mapped += HUGE_PAGE_SIZE;
                }

                if mapped < size {
                    debug!(
                        "map_identity recurse 1GiB 0x{:x} -- 0x{:x}",
                        base + mapped,
                        end
                    );
                    return self.map_identity(base + mapped, end);
                } else {
                    // Everything fit in 1 GiB ranges, We're done with mappings
                    return;
                }
            } else {
                debug!(
                    "We have less than 1 GiB to map 0x{:x} -- 0x{:x}",
                    base,
                    base + size
                );
                pdpt[pdpt_idx] = self.new_pd();
            }
        }
        assert!(pdpt[pdpt_idx].is_present());
        assert!(!pdpt[pdpt_idx].is_page());

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let mut pd_idx = pd_index(base);
        if !pd[pd_idx].is_present() {
            let vaddr_pos: usize =
                GIB_512 * pml4_idx + HUGE_PAGE_SIZE * pdpt_idx + LARGE_PAGE_SIZE * pd_idx;

            // In case we can map something at a 2 MiB granularity and
            // we still have at least 2 MiB to map create large page mappings
            if base.as_usize() == vaddr_pos && size > LARGE_PAGE_SIZE {
                let mut mapped = 0;
                // Add entries as long as we are within this allocated PDPT table
                // and have at least 1 GiB things to map
                while mapped < size && ((size - mapped) > LARGE_PAGE_SIZE) && pd_idx < 512 {
                    let paddr: PAddr = PAddr::from_u64((base + mapped).as_u64());
                    pd[pd_idx] = PDEntry::new(paddr, PDFlags::P | PDFlags::RW | PDFlags::PS);
                    debug!(
                        "Mapping 2 MiB range 0x{:x} -- 0x{:x}",
                        base + mapped,
                        (base + mapped) + LARGE_PAGE_SIZE
                    );

                    pd_idx += 1;
                    mapped += LARGE_PAGE_SIZE;
                }

                if mapped < size {
                    debug!(
                        "map_identity recurse 2MiB 0x{:x} -- 0x{:x}",
                        base + mapped,
                        end
                    );
                    return self.map_identity(base + mapped, end);
                } else {
                    // Everything fit in 2 MiB ranges, We're done with mappings
                    return;
                }
            } else {
                debug!(
                    "We have less than 2 MiB to map 0x{:x} -- 0x{:x}",
                    base,
                    base + size
                );
                pd[pd_idx] = self.new_pt();
            }
        }
        assert!(pd[pd_idx].is_present());
        assert!(!pd[pd_idx].is_page());

        let pt = self.get_pt(pd[pd_idx]);

        let mut pt_idx = pt_index(base);
        let mut mapped: usize = 0;
        while mapped < size && pt_idx < 512 {
            if !pt[pt_idx].is_present() {
                let paddr: PAddr = PAddr::from_u64((base + mapped).as_u64());

                pt[pt_idx] = PTEntry::new(paddr, PTFlags::P | PTFlags::RW); // |
                                                                            //PTFlags::US);
                debug!("Mapped 4KiB page: {:?}", pt[pt_idx]);
            }

            mapped += BASE_PAGE_SIZE;
            pt_idx += 1;
        }

        // Need go to different PD/PDPT/PML4 slot
        if mapped < size {
            debug!("map_identity recurse 0x{:x} -- 0x{:x}", base + mapped, end);
            return self.map_identity(base + mapped, end);
        }
        // else return
    }

    pub(crate) fn allocate_one_page() -> usize {
        let st = system_table();
        unsafe {
            match st.as_ref().boot_services().allocate_pages(
                AllocateType::AnyPages,
                uefi::table::boot::MemoryType(KernelPT),
                1,
            ) {
                Ok(num) => {
                    //info!("managed to allocate pages {} @ addr {:x}",
                    //    1, num);
                    st.as_ref().boot_services().memset(
                        num.unwrap() as *mut u8,
                        BASE_PAGE_SIZE,
                        0u8,
                    );
                    return num.unwrap() as usize;
                }
                Err(status) => panic!("failed to allocate {:?}", status),
            }
        }
    }

    fn new_page(&mut self) -> PTEntry {
        let paddr: PAddr = PAddr::from_u64(VSpace::allocate_one_page() as u64);
        return PTEntry::new(paddr, PTFlags::P | PTFlags::RW);
    }

    fn new_pt(&mut self) -> PDEntry {
        let paddr: PAddr = PAddr::from_u64(VSpace::allocate_one_page() as u64);
        return PDEntry::new(paddr, PDFlags::P | PDFlags::RW);
    }

    fn new_pd(&mut self) -> PDPTEntry {
        let paddr: PAddr = PAddr::from_u64(VSpace::allocate_one_page() as u64);
        return PDPTEntry::new(paddr, PDPTFlags::P | PDPTFlags::RW);
    }

    fn new_pdpt(&mut self) -> PML4Entry {
        let paddr: PAddr = PAddr::from_u64(VSpace::allocate_one_page() as u64);
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

    /// Do page-table walk to find physical address of a page.
    pub(crate) fn resolve(&self, base: VAddr) -> Option<PAddr> {
        let pml4_idx = pml4_index(base);
        if self.pml4[pml4_idx].is_present() {
            let pdpt_idx = pdpt_index(base);
            let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
            if pdpt[pdpt_idx].is_present() {
                let pd_idx = pd_index(base);
                let pd = self.get_pd(pdpt[pdpt_idx]);
                if pd[pd_idx].is_present() {
                    let pt_idx = pt_index(base);
                    let pt = self.get_pt(pd[pd_idx]);
                    if pt[pt_idx].is_present() {
                        return Some(pt[pt_idx].address());
                    }
                }
            }
        }

        None
    }

    /// Resolve a virtual address in the address space and return a
    /// kernel accessible page to it.
    fn resolve_to_page(&self, base: VAddr) -> Option<&mut [u8]> {
        match self.resolve(base) {
            Some(paddr) => {
                let kernel_addr = paddr_to_kernel_vaddr(paddr);
                Some(unsafe { transmute::<VAddr, &mut [u8; BASE_PAGE_SIZE as usize]>(kernel_addr) })
            }
            None => None,
        }
    }

    /// Fills a page in the virtual address space with the contents from region.
    /// XXX: Check that region length <= page length...
    pub fn fill(&self, address: VAddr, region: &[u8]) -> bool {
        match self.resolve_to_page(address) {
            Some(page) => {
                for (idx, b) in region.iter().enumerate() {
                    page[idx] = *b;
                }
                true
            }
            None => {
                info!("Unable to resolve {:?}", address);
                false
            }
        }
    }

    /// Back a region of virtual address space with physical memory.
    pub fn map(&mut self, base: VAddr, size: usize) {
        let pml4_idx = pml4_index(base);
        info!(
            "map base {:x} to pml4 {:p} @ pml4_idx {}",
            base, self.pml4, pml4_idx
        );
        if !self.pml4[pml4_idx].is_present() {
            self.pml4[pml4_idx] = self.new_pdpt();
        }
        assert!(self.pml4[pml4_idx].is_present());

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let pdpt_idx = pdpt_index(base);
        if !pdpt[pdpt_idx].is_present() {
            pdpt[pdpt_idx] = self.new_pd();
        }
        assert!(pdpt[pdpt_idx].is_present());

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let pd_idx = pd_index(base);
        if !pd[pd_idx].is_present() {
            pd[pd_idx] = self.new_pt();
        }
        assert!(pd[pd_idx].is_present());

        let pt = self.get_pt(pd[pd_idx]);

        let mut pt_idx = pt_index(base);
        let mut mapped = 0;
        while mapped < size && pt_idx < 512 {
            if !pt[pt_idx].is_present() {
                pt[pt_idx] = self.new_page();
                debug!("Mapped 4KiB page: {:?}", pt[pt_idx]);
            } else {
                error!("overwriting existing page??");
            }
            assert!(pt[pt_idx].is_present());

            pt_idx += 1;
            mapped += BASE_PAGE_SIZE as usize;
        }

        // Need go to different PD/PDPT/PML4 slot
        if mapped < size {
            self.map(base + mapped, size - mapped);
        }
    }
}

pub const KernelElf: u32 = 0x80000001;
pub const KernelPT: u32 = 0x80000002;
pub const KernelStack: u32 = 0x80000003;
pub const UefiMemoryMap: u32 = 0x80000004;

pub const KERNEL_OFFSET: usize = 0x400000000000;

pub struct Kernel<'a> {
    pub mapping: Vec<(usize, usize)>,
    pub vspace: VSpace<'a>,
}


impl<'a> elfloader::ElfLoader for Kernel<'a> {
    /// Makes sure the process vspace is backed for the region reported by the elf loader.
    fn allocate(&mut self, base: usize, size: usize, _flags: elf::ProgFlag) {
        info!("allocate: 0x{:x} -- 0x{:x}", base, base + size);
        let base = base;
        let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        self.vspace.map(VAddr::from(base), rsize);
    }

    /// Load a region of bytes into the virtual address space of the process.
    /// XXX: Report error if that region is not backed by memory (i.e., allocate was not called).
    fn load(&mut self, destination: usize, region: &'static [u8]) {
        info!(
            "load from elf: 0x{:x} -- 0x{:x}",
            destination,
            destination + region.len()
        );

        for (idx, subregion) in region.chunks(BASE_PAGE_SIZE as usize).enumerate() {
            let base_vaddr = destination + idx * BASE_PAGE_SIZE as usize;
            info!("loading content at: 0x{:x}", base_vaddr);
            self.vspace.fill(VAddr::from(base_vaddr), subregion);
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

