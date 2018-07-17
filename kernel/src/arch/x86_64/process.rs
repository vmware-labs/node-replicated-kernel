use core::fmt;
use core::mem::transmute;

use elfloader::elf;
use elfloader::ElfLoader;

use x86::bits64::paging;
use x86::bits64::paging::{
    pd_index, pdpt_index, pml4_index, pt_index, PML4, PML4Entry, BASE_PAGE_SIZE,
};
use x86::bits64::rflags;
use x86::controlregs;

use super::gdt;
use super::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr};

use arch::irq;
use mm::{BespinPageTableProvider, PageTableProvider};
use mutex::Mutex;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

#[no_mangle]
pub static CURRENT_PROCESS: Mutex<Option<Process<'static>>> = mutex!(None);

pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
    pager: BespinPageTableProvider,
}

impl<'a> VSpace<'a> {
    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt<'b>(&self, entry: PML4Entry) -> &'b mut paging::PDPT {
        unsafe { transmute::<VAddr, &mut paging::PDPT>(paddr_to_kernel_vaddr(entry.get_address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd<'b>(&self, entry: paging::PDPTEntry) -> &'b mut paging::PD {
        unsafe { transmute::<VAddr, &mut paging::PD>(paddr_to_kernel_vaddr(entry.get_address())) }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt<'b>(&self, entry: paging::PDEntry) -> &'b mut paging::PT {
        unsafe { transmute::<VAddr, &mut paging::PT>(paddr_to_kernel_vaddr(entry.get_address())) }
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
                slog!("Unable to resolve {:?}", address);
                false
            }
        }
    }

    /// Back a region of virtual address space with physical memory.
    pub fn map(&mut self, base: VAddr, size: usize) {
        let pml4_idx = pml4_index(base);
        if !self.pml4[pml4_idx].contains(paging::PML4Entry::P) {
            self.pml4[pml4_idx] = self.pager.new_pdpt().unwrap();
        }
        assert!(self.pml4[pml4_idx].contains(paging::PML4Entry::P));

        let pdpt = self.get_pdpt(self.pml4[pml4_idx]);
        let pdpt_idx = pdpt_index(base);
        if !pdpt[pdpt_idx].contains(paging::PDPTEntry::P) {
            pdpt[pdpt_idx] = self.pager.new_pd().unwrap();
        }
        assert!(pdpt[pdpt_idx].contains(paging::PDPTEntry::P));

        let pd = self.get_pd(pdpt[pdpt_idx]);
        let pd_idx = pd_index(base);
        if !pd[pd_idx].contains(paging::PDEntry::P) {
            pd[pd_idx] = self.pager.new_pt().unwrap();
        }
        assert!(pd[pd_idx].contains(paging::PDEntry::P));

        let pt = self.get_pt(pd[pd_idx]);

        let mut pt_idx = pt_index(base);
        let mut mapped = 0;
        while mapped < size && pt_idx < 512 {
            if !pt[pt_idx].contains(paging::PTEntry::P) {
                pt[pt_idx] = self.pager.new_page().unwrap();
                slog!("Mapped 4KiB page: {:?}", pt[pt_idx]);
            }
            assert!(pt[pt_idx].contains(paging::PTEntry::P));

            pt_idx += 1;
            mapped += paging::BASE_PAGE_SIZE as usize;
        }

        // Need go to different PD/PDPT/PML4 slot
        if mapped < size {
            self.map(base + mapped, size - mapped);
        }
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
        slog!("ABOUT TO GO TO USER-SPACE");
        let user_flags = rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF;
        unsafe {
            let pml4_phys: PAddr =
                kernel_vaddr_to_paddr(transmute::<&PML4Entry, VAddr>(&self.vspace.pml4[0]));
            slog!("switching to 0x{:x}", pml4_phys);
            controlregs::cr3_write(pml4_phys as PAddr);
        };
        unsafe {
            asm!("jmp exec" :: "{rcx}" (entry_point as u64) "{r11}" (user_flags));
        }
        panic!("Should not come here!");
    }

    pub fn resume(&self) {
        let user_rflags = rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF;
        slog!("resuming User-space");
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
    fn allocate(&mut self, base: usize, size: usize, _flags: elf::ProgFlag) {
        slog!("allocate: 0x{:x} -- 0x{:x}", base, base + size);
        let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        self.vspace.map(base, rsize);
    }

    /// Load a region of bytes into the virtual address space of the process.
    /// XXX: Report error if that region is not backed by memory (i.e., allocate was not called).
    fn load(&mut self, destination: usize, region: &'static [u8]) {
        slog!(
            "load: 0x{:x} -- 0x{:x}",
            destination,
            destination + region.len()
        );

        for (idx, subregion) in region.chunks(BASE_PAGE_SIZE as usize).enumerate() {
            let base_vaddr = destination + idx * BASE_PAGE_SIZE as usize;
            self.vspace.fill(base_vaddr, subregion);
        }
    }
}
