use prelude::*;

use core::mem::{transmute};
use super::memory::{PAddr, VAddr};
use ::mm::{FrameManager, paddr_to_kernel_vaddr};

use elfloader::{ElfLoader};
use elfloader::elf;
use x86::mem::{PML4, PML4Entry, BASE_PAGE_SIZE, pml4_index, pdpt_index, pd_index, pt_index};
use x86::mem;
//use std::option;

macro_rules! round_up {
   ( $num:expr, $s:expr ) => { (($num + $s - 1) / $s) * $s }
}

pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
    fm: &'a mut FrameManager,
}

impl<'a> VSpace<'a> {

    /// Allocate a new page directory and return a PML4 entry for it.
    fn new_pdpt(&mut self) -> Option<PML4Entry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(PML4Entry::new(frame.base, mem::PML4_P))
            },
            None => None
        }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut mem::PDPT {
        unsafe {
            transmute::<VAddr, &mut mem::PDPT>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<mem::PDPTEntry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(mem::PDPTEntry::new(frame.base, mem::PDPT_P))
            },
            None => None
        }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd<'b>(&self, entry: mem::PDPTEntry) -> &'b mut mem::PD {
        unsafe {
            transmute::<VAddr, &mut mem::PD>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<mem::PDEntry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(mem::PDEntry::new(frame.base, mem::PD_P))
            },
            None => None
        }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt<'b>(&self, entry: mem::PDEntry) -> &'b mut mem::PT {
        unsafe {
            transmute::<VAddr, &mut mem::PT>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<mem::PTEntry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(mem::PTEntry::new(frame.base, mem::PT_P))
            },
            None => None
        }
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
                        return Some(pt[pt_idx].get_address());
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
            Some(paddr) =>
            {
                let kernel_addr = paddr_to_kernel_vaddr(paddr);
                Some(unsafe { transmute::<VAddr, &mut [u8; BASE_PAGE_SIZE as usize]>(kernel_addr) })
            }
            None => None
        }
    }

    /// Fills a page in the virtual address space with the contents from region.
    /// XXX: Check that region length <= page length...
    pub fn fill(&self, address: VAddr, region: &[u8]) -> bool {
        match self.resolve_to_page(address) {
            Some(page) =>
            {
                for (idx, b) in region.iter().enumerate() {
                    page[idx] = *b;
                }
                true
            }
            None => { log!("Unable to resolve {:?}", address); false }
        }
    }

    /// Back a region of virtual address space with physical memory.
    pub fn map(&mut self, base: VAddr, size: usize) {
        let pml4_idx = pml4_index(base);
        if !self.pml4[pml4_idx].contains(mem::PML4_P) {
            self.pml4[pml4_idx] = self.new_pdpt().unwrap();
        }
        assert!(self.pml4[pml4_idx].contains(mem::PML4_P));

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let pdpt_idx = pdpt_index(base);
        if !pdpt[pdpt_idx].contains(mem::PDPT_P) {
            pdpt[pdpt_idx] = self.new_pd().unwrap();
        }
        assert!(pdpt[pdpt_idx].contains(mem::PDPT_P));

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let pd_idx = pd_index(base);
        if !pd[pd_idx].contains(mem::PD_P) {
            pd[pd_idx] = self.new_pt().unwrap();
        }
        assert!(pd[pd_idx].contains(mem::PD_P));

        let pt = self.get_pt(pd[pd_idx]);

        let mut pt_idx = pt_index(base);
        let mut mapped = 0;
        while mapped < size && pt_idx < 512 {
            if !pt[pt_idx].contains(mem::PT_P) {
                pt[pt_idx] = self.new_page().unwrap();
                log!("Mapped 4KiB page: {:?}", pt[pt_idx]);
            }
            assert!(pt[pt_idx].contains(mem::PT_P));

            pt_idx += 1;
            mapped += mem::BASE_PAGE_SIZE as usize;
        }

        // Need go to different PD/PDPT/PML4 slot
        if (mapped < size) {
            self.map(base + mapped, size - mapped);
        }
    }
}

pub struct Process<'a> {
    pub pid: u64,
    pub vspace: VSpace<'a>,
}

impl<'a> Process<'a> {
    pub fn new<'b>(fm: &'b mut FrameManager) -> Option<Process> {
        let pml4 = fm.allocate_pml4();
        match pml4 {

            Some(table) => {
                Some(Process{pid: 0, vspace: VSpace{fm: fm, pml4: table} })
            }
            None => None
        }
    }
}

impl<'a> ElfLoader for Process<'a> {

    /// Makes sure the process vspace is backed for the region reported by the elf loader.
    fn allocate(&mut self, base: VAddr, size: usize, flags: elf::ProgFlag) {
        log!("allocate: 0x{:x} -- 0x{:x}", base, base+size);
        let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        self.vspace.map(base, size);
    }

    /// Load a region of bytes into the virtual address space of the process.
    /// XXX: Report error if that region is not backed by memory (i.e., allocate was not called).
    fn load(&mut self, destination: VAddr, region: &'static [u8]) {
        log!("load: 0x{:x} -- 0x{:x}", destination, destination+region.len());

        for (idx, subregion) in region.chunks(BASE_PAGE_SIZE as usize).enumerate() {
            let base_vaddr = destination + idx*BASE_PAGE_SIZE as usize;
            self.vspace.fill(base_vaddr, subregion);
        }

    }
}