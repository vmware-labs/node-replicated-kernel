use core::fmt;
use core::mem::transmute;

use elfloader::ElfLoader;

use x86::bits64::paging;
use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

use super::gdt;

use super::irq;
use super::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr};
use crate::memory::{BespinPageTableProvider, PageTableProvider};
use crate::mutex::Mutex;

const GIB_512: usize = 512 * 512 * 512 * 0x1000;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

#[no_mangle]
pub static CURRENT_PROCESS: Mutex<Option<Process<'static>>> = mutex!(None);

pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
    pub pager: BespinPageTableProvider,
}

impl<'a> VSpace<'a> {
    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut paging::PDPT {
        unsafe { transmute::<VAddr, &mut paging::PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd<'b>(&self, entry: paging::PDPTEntry) -> &'b mut paging::PD {
        unsafe { transmute::<VAddr, &mut paging::PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt<'b>(&self, entry: paging::PDEntry) -> &'b mut paging::PT {
        unsafe { transmute::<VAddr, &mut paging::PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Do page-table walk to find physical address of a page.
    fn resolve(&self, base: VAddr) -> Option<PAddr> {
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
                debug!("Unable to resolve {:?}", address);
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
            self.pml4[pml4_idx] = self.pager.new_pdpt().unwrap();
        }
        assert!(self.pml4[pml4_idx].is_present());

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let pdpt_idx = pdpt_index(base);
        if !pdpt[pdpt_idx].is_present() {
            pdpt[pdpt_idx] = self.pager.new_pd().unwrap();
        }
        assert!(pdpt[pdpt_idx].is_present());

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let pd_idx = pd_index(base);
        if !pd[pd_idx].is_present() {
            pd[pd_idx] = self.pager.new_pt().unwrap();
        }
        assert!(pd[pd_idx].is_present());

        let pt = self.get_pt(pd[pd_idx]);

        let mut pt_idx = pt_index(base);
        let mut mapped = 0;
        while mapped < size && pt_idx < 512 {
            if !pt[pt_idx].is_present() {
                pt[pt_idx] = self.pager.new_page().unwrap();
                debug!("Mapped 4KiB page: {:?}", pt[pt_idx]);
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

    pub fn map_identity(&mut self, base: VAddr, end: VAddr) {
        let size: usize = (end - base).into();
        debug!("map_identity 0x{:x} -- 0x{:x}", base, end);

        let pml4_idx = pml4_index(base);
        //info!("map base {:x} to pml4 {:p} @ pml4_idx {}", base, self.pml4, pml4_idx);
        if !self.pml4[pml4_idx].is_present() {
            self.pml4[pml4_idx] = self.pager.new_pdpt().unwrap();
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
                pdpt[pdpt_idx] = self.pager.new_pd().unwrap();
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
                pd[pd_idx] = self.pager.new_pt().unwrap();
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
}

pub struct Process<'a> {
    pub save_area: irq::SaveArea,
    pub pid: u64,
    pub vspace: VSpace<'a>,
}

impl<'a> Process<'a> {
    pub fn new<'b>(pid: u64) -> Option<Process<'a>> {
        let mut pager = BespinPageTableProvider::new();
        pager.allocate_pml4().map(|pml4| Process {
            pid: pid,
            vspace: VSpace {
                pml4: pml4,
                pager: pager,
            },
            save_area: Default::default(),
        })
    }

    pub fn start(&self, entry_point: VAddr) {
        debug!("ABOUT TO GO TO USER-SPACE");
        let user_flags = rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF;
        unsafe {
            let pml4_phys: PAddr =
                kernel_vaddr_to_paddr(transmute::<&PML4Entry, VAddr>(&self.vspace.pml4[0]));
            debug!("switching to 0x{:x}", pml4_phys);
            controlregs::cr3_write(pml4_phys.into());
        };
        unsafe {
            asm!("jmp exec" :: "{rcx}" (entry_point) "{r11}" (user_flags));
        }
        panic!("Should not come here!");
    }

    pub fn resume(&self) {
        let user_rflags = rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF;
        debug!("resuming User-space");
        unsafe {
            // %rbx points to save_area
            // %r8 points to ss
            // %r9 points to cs
            // %r10 points to rflags

            asm!("jmp resume" ::
                 "{r8}"  (gdt::get_user_stack_selector().bits() as u64)
                 "{r9}"  (gdt::get_user_code_selector().bits() as u64)
                 "{r10}" (user_rflags.bits() as u64));
        }
        panic!("Should not come here!");
    }
}

impl<'a> fmt::Debug for Process<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Process: {}\nSaveArea: {:?}", self.pid, self.save_area)
    }
}

impl<'a> ElfLoader for Process<'a> {
    /// Makes sure the process vspace is backed for the region reported by the elf loader.
    fn allocate(
        &mut self,
        base: u64,
        size: usize,
        _flags: elfloader::Flags,
    ) -> Result<(), &'static str> {
        debug!("allocate: 0x{:x} -- 0x{:x}", base, base as usize + size);
        let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        self.vspace.map(VAddr::from(base), rsize);
        Ok(())
    }

    /// Load a region of bytes into the virtual address space of the process.
    /// XXX: Report error if that region is not backed by memory (i.e., allocate was not called).
    fn load(&mut self, destination: u64, region: &[u8]) -> Result<(), &'static str> {
        debug!(
            "load: 0x{:x} -- 0x{:x}",
            destination,
            destination as usize + region.len()
        );

        for (idx, subregion) in region.chunks(BASE_PAGE_SIZE as usize).enumerate() {
            let base_vaddr = destination as usize + idx * BASE_PAGE_SIZE as usize;
            self.vspace.fill(VAddr::from(base_vaddr), subregion);
        }
        Ok(())
    }

    fn relocate(
        &mut self,
        entry: &elfloader::Rela<u64>,
        original_base: u64,
    ) -> Result<(), &'static str> {
        debug!("relocate: {:?}", entry);

        Ok(())
    }
}
