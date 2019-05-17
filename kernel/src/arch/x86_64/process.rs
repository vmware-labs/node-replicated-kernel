use core::fmt;
use core::mem::transmute;
use core::ptr;

use alloc::vec::Vec;

use elfloader::ElfLoader;

use x86::bits64::paging;
use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

use super::gdt;

use crate::is_page_aligned;
use crate::round_up;

use super::irq;
use super::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, PAddr, VAddr};
use crate::memory::PageTableProvider;
use crate::mutex::Mutex;

use super::memory::KERNEL_BASE;
use crate::memory::BespinPageTableProvider;

use super::vspace::*;

use crate::error::KError;

#[no_mangle]
pub static CURRENT_PROCESS: Mutex<Option<Process>> = mutex!(None);

pub struct Process {
    pub mapping: Vec<(VAddr, usize, u64, MapAction)>,
    pub save_area: irq::SaveArea,
    pub pid: u64,
    pub vspace: VSpace,

    pub offset: VAddr,
    pub entry_point: VAddr,
}

impl Process {
    pub fn from(module: crate::arch::Module) -> Result<Process, KError> {
        let mut p = Process::new(0);
        // Safe since we don't modify the kernel page-table
        unsafe {
            let e = elfloader::ElfBinary::new(module.name(), module.as_slice())?;
            p.entry_point = VAddr::from(e.entry_point());
            e.load(&mut p)?;
        }

        super::kcb::try_get_kcb().map(|kcb| {
            let kernel_pml_entry = kcb.init_vspace().pml4[128];
            info!("KERNEL MAPPINGS {:?}", kernel_pml_entry);
            p.vspace.pml4[128] = kernel_pml_entry;
        });


        Ok(p)
    }


    pub fn new<'b>(pid: u64) -> Process {
        unsafe {
            Process {
                offset: VAddr::from(0usize),
                mapping: Vec::with_capacity(64),
                pid: pid,
                vspace: VSpace::new(),
                save_area: Default::default(),
                entry_point: VAddr::from(0usize),
            }
        }
    }

    pub fn start(&self) -> ! {
        info!("About to go to user-space");
        let user_flags = rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF;

        let pml4_physical = self.vspace.pml4_address();

        unsafe {

            //super::vspace::dump_current_table(1);
            //super::vspace::dump_table(&self.vspace.pml4, 4);

            info!("Switching to 0x{:x}", pml4_physical);
            controlregs::cr3_write(pml4_physical.into());
            x86::tlb::flush_all();
            info!("Switched to 0x{:x}", pml4_physical);
        };

        info!(
            "Jumping to {:#x}",
            (self.offset + self.entry_point).as_u64()
        );
        unsafe {
            asm!("jmp exec" :: "{rcx}" ((self.offset + self.entry_point).as_u64()) "{r11}" (user_flags));
        }

        unreachable!("We should not come here!");
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

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Process: {}\nSaveArea: {:?}", self.pid, self.save_area)
    }
}

impl elfloader::ElfLoader for Process {
    /// Makes sure the process vspace is backed for the regions
    /// reported by the ELF loader as loadable.
    ///
    /// Our strategy is to first figure out how much space we need,
    /// then allocate a single chunk of physical memory and
    /// map the individual pieces of it with different access rights.
    /// This has the advantage that our address space is
    /// all a very simple 1:1 mapping of physical memory.
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
                (false, false, false) => panic!("MapAction::None"),
                (true, false, false) => panic!("MapAction::None"),
                (false, true, false) => panic!("MapAction::None"),
                (false, false, true) => MapAction::ReadUser,
                (true, false, true) => MapAction::ReadExecuteUser,
                (true, true, false) => panic!("MapAction::None"),
                (false, true, true) => MapAction::ReadWriteUser,
                (true, true, true) => MapAction::ReadWriteExecuteUser,
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
            ResourceType::Binary,
            max_alignment,
        );

        self.offset = VAddr::from(pbase.as_usize());
        info!(
            "Binary loaded at address: {:#x} entry {:#x}",
            self.offset, self.entry_point
        );

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
        info!(
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
        let addr = self.offset.as_u64() + entry.get_offset();
        info!("ELF relocation");

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

        let _from: VAddr = self.offset + (base & !0xfff); // Round down to nearest page-size
        let _to = self.offset + base + size;
        Ok(())
    }
}

