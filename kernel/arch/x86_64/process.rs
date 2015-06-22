use prelude::*;

use core::cell::RefCell;
use core::mem::{transmute};
use core::fmt;

use elfloader::{ElfLoader};
use elfloader::elf;
use x86::paging::{PML4, PML4Entry, BASE_PAGE_SIZE, pml4_index, pdpt_index, pd_index, pt_index};
use x86::paging;
use x86::rflags;
use x86::controlregs;

use super::gdt;
use super::memory::{PAddr, VAddr};
use ::mm::{paddr_to_kernel_vaddr, kernel_vaddr_to_paddr, fmanager};
use ::mutex::{Mutex};

macro_rules! round_up {
   ( $num:expr, $s:expr ) => { (($num + $s - 1) / $s) * $s }
}

#[no_mangle]
pub static current_process: Mutex<Option<Process<'static>>> = mutex!(None);

pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
}

impl<'a> VSpace<'a> {

    /// Allocate a new page directory and return a PML4 entry for it.
    fn new_pdpt(&mut self) -> Option<PML4Entry> {
        let mut fm = fmanager.lock();
        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(PML4Entry::new(frame.base, paging::PML4_P | paging::PML4_RW | paging::PML4_US))
            },
            None => None
        }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut paging::PDPT {
        unsafe {
            transmute::<VAddr, &mut paging::PDPT>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<paging::PDPTEntry> {
        let mut fm = fmanager.lock();
        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(paging::PDPTEntry::new(frame.base, paging::PDPT_P | paging::PDPT_RW | paging::PDPT_US))
            },
            None => None
        }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd<'b>(&self, entry: paging::PDPTEntry) -> &'b mut paging::PD {
        unsafe {
            transmute::<VAddr, &mut paging::PD>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<paging::PDEntry> {
        let mut fm = fmanager.lock();
        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(paging::PDEntry::new(frame.base, paging::PD_P | paging::PD_RW | paging::PD_US))
            },
            None => None
        }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt<'b>(&self, entry: paging::PDEntry) -> &'b mut paging::PT {
        unsafe {
            transmute::<VAddr, &mut paging::PT>(paddr_to_kernel_vaddr(entry.get_address()))
        }
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<paging::PTEntry> {
        let mut fm = fmanager.lock();
        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                Some(paging::PTEntry::new(frame.base, paging::PT_P | paging::PT_RW | paging::PT_US))
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
        if !self.pml4[pml4_idx].contains(paging::PML4_P) {
            self.pml4[pml4_idx] = self.new_pdpt().unwrap();
        }
        assert!(self.pml4[pml4_idx].contains(paging::PML4_P));

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let pdpt_idx = pdpt_index(base);
        if !pdpt[pdpt_idx].contains(paging::PDPT_P) {
            pdpt[pdpt_idx] = self.new_pd().unwrap();
        }
        assert!(pdpt[pdpt_idx].contains(paging::PDPT_P));

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let pd_idx = pd_index(base);
        if !pd[pd_idx].contains(paging::PD_P) {
            pd[pd_idx] = self.new_pt().unwrap();
        }
        assert!(pd[pd_idx].contains(paging::PD_P));

        let pt = self.get_pt(pd[pd_idx]);

        let mut pt_idx = pt_index(base);
        let mut mapped = 0;
        while mapped < size && pt_idx < 512 {
            if !pt[pt_idx].contains(paging::PT_P) {
                pt[pt_idx] = self.new_page().unwrap();
                log!("Mapped 4KiB page: {:?}", pt[pt_idx]);
            }
            assert!(pt[pt_idx].contains(paging::PT_P));

            pt_idx += 1;
            mapped += paging::BASE_PAGE_SIZE as usize;
        }

        // Need go to different PD/PDPT/PML4 slot
        if (mapped < size) {
            self.map(base + mapped, size - mapped);
        }
    }
}

#[derive(Default)]
#[repr(C, packed)]
pub struct SaveArea {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8:  u64,
    r9:  u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

pub struct Process<'a> {
    pub save_area: SaveArea,
    pub pid: u64,
    pub vspace: VSpace<'a>,
}

impl<'a> Process<'a> {
    pub fn new<'b>(pid: u64) -> Option<Process<'a>> {
        let mut fm = fmanager.lock();
        let pml4 = fm.allocate_pml4();
        match pml4 {

            Some(table) => {
                Some(Process{pid: pid, vspace: VSpace{pml4: table}, save_area: Default::default() })
            }
            None => None
        }
    }

    pub fn start(&self, entry_point: VAddr) {
        log!("ABOUT TO GO TO USER-SPACE");
        let user_flags = rflags::RFLAGS_A1 | rflags::RFLAGS_IF;
        unsafe {
            let pml4_phys: PAddr = kernel_vaddr_to_paddr(transmute::<&PML4Entry, VAddr>(&self.vspace.pml4[0]));
            log!("switching to 0x{:x}", pml4_phys);
            controlregs::cr3_write(pml4_phys as PAddr);
        };
        unsafe {
            asm!("jmp exec" :: "{ecx}" (entry_point as u64) "{r11}" (user_flags));
        }
        panic!("Should not come here!");
    }

    pub fn resume(&self) {
        let user_ss = 0;
        let user_cs = 0;
        let user_rflags = rflags::RFLAGS_A1 | rflags::RFLAGS_IF;
        log!("resuming User-space");
        unsafe {
            // %rbx points to save_area
            // %r8 points to ss
            // %r9 points to cs
            // %r10 points to rflags

            asm!("jmp resume" ::
                 "{r8}"  (gdt::get_user_stack_selector())
                 "{r9}"  (gdt::get_user_code_selector())
                 "{r10}" (user_rflags));
        }
        panic!("Should not come here!");
    }
}

impl<'a> fmt::Debug for Process<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Process: {}\nSaveArea: {:?}", self.pid, self.save_area)
    }
}

impl fmt::Debug for SaveArea {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
"rax = {:>16x} rcx = {:>16x}
rbx = {:>16x} rdx = {:>16x}
rsi = {:>16x} rdi = {:>16x}
rbp = {:>16x} r8  = {:>16x}
r9  = {:>16x} r10 = {:>16x}
r11 = {:>16x} r12 = {:>16x}
r13 = {:>16x} r14 = {:>16x}
r15 = {:>16x} rip = {:>16x}",
            self.rax,
            self.rcx,
            self.rbx,
            self.rdx,
            self.rsi,
            self.rdi,
            self.rbp,
            self.r8,
            self.r9,
            self.r10,
            self.r11,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.rip)
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