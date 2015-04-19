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

    fn new_pdpt(&mut self) -> Option<PML4Entry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(PML4Entry::new(frame.base, mem::PML4_P))
            },
            None => None
        }
    }

    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut mem::PDPT {
        unsafe {
            transmute::<VAddr, &mut mem::PDPT>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }


    fn new_pd(&mut self) -> Option<mem::PDPTEntry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(mem::PDPTEntry::new(frame.base, mem::PDPT_P))
            },
            None => None
        }
    }

    fn get_pd<'b>(&self, entry: mem::PDPTEntry) -> &'b mut mem::PD {
        unsafe {
            transmute::<VAddr, &mut mem::PD>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    fn new_pt(&mut self) -> Option<mem::PDEntry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(mem::PDEntry::new(frame.base, mem::PD_P))
            },
            None => None
        }
    }

    fn get_pt<'b>(&self, entry: mem::PDEntry) -> &'b mut mem::PT {
        unsafe {
            transmute::<VAddr, &mut mem::PT>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    fn new_page(&mut self) -> Option<mem::PTEntry> {
        match self.fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(mem::PTEntry::new(frame.base, mem::PT_P))
            },
            None => None
        }
    }


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
        let pt_idx = pt_index(base);

        // TODO: Now back stuff with pages until we need another PD/PDPT etc.
        if !pt[pt_idx].contains(mem::PT_P) {
            pt[pt_idx] = self.new_page().unwrap();
        }
        assert!(pt[pt_idx].contains(mem::PT_P));
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
    fn allocate(&mut self, base: VAddr, size: usize, flags: elf::ProgFlag) {
        let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        let frame = self.vspace.fm.allocate_frame(rsize as u64);

        match frame {
            Some(f) => log!("frame = {:?}", f),
            None => log!("Not enough mem")
        };

        self.vspace.map(base, size);
    }

    fn load(&mut self, destination: VAddr, region: &'static [u8]) {
        log!("load: {}", destination);
    }
}