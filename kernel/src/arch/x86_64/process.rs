use core::fmt;
use core::mem::transmute;
use core::ptr;

use elfloader::ElfLoader;

use x86::bits64::paging;
use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

use super::gdt;

use super::irq;
use super::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr};
use crate::memory::PageTableProvider;
use crate::mutex::Mutex;

use super::memory::KERNEL_BASE;
use crate::memory::BespinPageTableProvider;

use super::vspace::*;


macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

#[no_mangle]
pub static CURRENT_PROCESS: Mutex<Option<Process<'static>>> = mutex!(None);


pub struct Process<'a> {
    pub save_area: irq::SaveArea,
    pub pid: u64,
    pub vspace: VSpace<'a>,
}

impl<'a> Process<'a> {
    pub fn new<'b>(pid: u64) -> Process<'a> {
        unsafe {
            Process {
                pid: pid,
                vspace: VSpace {
                    pml4: transmute::<VAddr, &mut PML4>(VAddr::from(0x0usize)),
                },
                save_area: Default::default(),
            }
        }
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
    fn allocate(&mut self, load_headers: elfloader::LoadableHeaders) -> Result<(), &'static str> {
        //debug!("allocate: 0x{:x} -- 0x{:x}", base, base as usize + size);
        //let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        //self.vspace.map(VAddr::from(base), rsize);
        panic!("NYI");
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

        /*for (idx, subregion) in region.chunks(BASE_PAGE_SIZE as usize).enumerate() {
            let base_vaddr = destination as usize + idx * BASE_PAGE_SIZE as usize;
            self.vspace.fill(VAddr::from(base_vaddr), subregion);
        }*/
        unimplemented!();
        Ok(())
    }

    fn relocate(&mut self, entry: &elfloader::Rela<u64>) -> Result<(), &'static str> {
        debug!("relocate: {:?}", entry);

        Ok(())
    }
}
