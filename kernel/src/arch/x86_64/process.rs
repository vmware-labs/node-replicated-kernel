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
pub static mut CURRENT_PROCESS: Mutex<Option<&mut Process>> = mutex!(None);

/// A process representation.
#[repr(C, packed)]
pub struct Process {
    /// CPU context save area (must be first, see exec.S).
    pub save_area: irq::SaveArea,
    /// ELF File mappings that were installed into the address space.
    pub mapping: Vec<(VAddr, usize, u64, MapAction)>,
    /// Process ID.
    pub pid: u64,
    /// The address space of the process.
    pub vspace: VSpace,
    /// Offset where ELF is located.
    pub offset: VAddr,
    /// The entry point of the ELF file.
    pub entry_point: VAddr,
    /// Initial allocated stack (base address).
    pub stack_base: VAddr,
    /// Initial allocated stack (top address).
    pub stack_top: VAddr,
    /// Initial allocated stack size.
    pub stack_size: usize,
}

impl Process {
    /// Create a process from a Module (i.e., a struct passed by UEFI)
    pub fn from(module: crate::arch::Module) -> Result<Process, KError> {
        let mut p = Process::new(0);

        // Load the Module into the process address-space
        // Safe since we don't modify the kernel page-table
        unsafe {
            let e = elfloader::ElfBinary::new(module.name(), module.as_slice())?;
            p.entry_point = VAddr::from(e.entry_point());
            e.load(&mut p)?;
        }

        // Allocate a stack
        p.vspace.map(
            p.stack_base,
            p.stack_size,
            MapAction::ReadWriteExecuteUser,
            BASE_PAGE_SIZE as u64,
        );

        // Install the kernel mappings
        super::kcb::try_get_kcb().map(|kcb| {
            let kernel_pml_entry = kcb.init_vspace().pml4[128];
            info!("KERNEL MAPPINGS {:?}", kernel_pml_entry);
            p.vspace.pml4[128] = kernel_pml_entry;
        });

        Ok(p)
    }

    /// Create a new `empty` process.
    fn new<'b>(pid: u64) -> Process {
        let stack_base = VAddr::from(0xadf000_0000usize);
        let stack_size = 128 * BASE_PAGE_SIZE;
        let stack_top = stack_base + stack_size - 8usize; // -8 due to x86 stack alignemnt requirements

        unsafe {
            Process {
                offset: VAddr::from(0usize),
                mapping: Vec::with_capacity(64),
                pid: pid,
                vspace: VSpace::new(),
                save_area: Default::default(),
                entry_point: VAddr::from(0usize),
                stack_base: stack_base,
                stack_top: stack_top,
                stack_size: stack_size,
            }
        }
    }

    /// Start the process (run it for the first time).
    pub fn start(&mut self) -> ! {
        info!("About to go to user-space");
        // TODO: For now we allow unconditional IO access from user-space
        let user_flags = rflags::RFlags::FLAGS_IOPL3 | rflags::RFlags::FLAGS_A1;

        let pml4_physical = self.vspace.pml4_address();

        unsafe {
            //super::vspace::dump_current_table(1);
            //super::vspace::dump_table(&self.vspace.pml4, 4);

            info!("Switching to 0x{:x}", pml4_physical);
            controlregs::cr3_write(pml4_physical.into());
            x86::tlb::flush_all();
            info!("Switched to 0x{:x}", pml4_physical);
        };

        unsafe {
            let mut p = CURRENT_PROCESS.lock();
            *p = Some(core::mem::transmute::<&mut Process, &'static mut Process>(
                self,
            ));
            info!("p {:?}", *p);
        }
        unsafe {
            info!("test process");
            let p = super::process::CURRENT_PROCESS.lock();
            info!("p {:?}\n\n\n{:p}", *p, &*p);
        }

        info!(
            "Jumping to {:#x}",
            (self.offset + self.entry_point).as_u64()
        );

        unsafe {
            asm!("jmp exec" ::
                "{rcx}" ((self.offset + self.entry_point).as_u64())
                "{r11}" (user_flags.bits())
                "{rsp}" (self.stack_top.as_u64())
                "{rbp}" (self.stack_top.as_u64())
            );
        }

        unreachable!("We should not come here!");
    }

    /// Resume the process (after it got interrupted or from a system call).
    pub fn resume(&self) {
        let user_rflags = rflags::RFlags::from_priv(x86::Ring::Ring3)
            | rflags::RFlags::FLAGS_A1
            | rflags::RFlags::FLAGS_IF;
        info!("resuming User-space {:?}", user_rflags.bits());
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
        write!(f, "Process {}:\nSaveArea: {:?}", self.pid, self.save_area)
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
                // TODO: Inefficient byte-wise copy
                // If this is allocated as a single block of physical memory
                // we can just do paddr_to_vaddr and memcopy
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
        let addr = self.offset + entry.get_offset();

        // Translate `addr` into a kernel vaddr we can write to:
        let paddr = self
            .vspace
            .resolve_addr(addr)
            .expect("Can't resolve address");
        let mut kernel_addr: VAddr = paddr_to_kernel_vaddr(paddr);

        debug!(
            "ELF relocation paddr {:#x} kernel_addr {:#x}",
            paddr, kernel_addr
        );

        use elfloader::TypeRela64;
        if let TypeRela64::R_RELATIVE = TypeRela64::from(entry.get_type()) {
            // This is a relative relocation of a 64 bit value, we add the offset (where we put our
            // binary in the vspace) to the addend and we're done:
            unsafe {
                // Scary unsafe changing stuff in random memory locations based on
                // ELF binary values weee!
                *(kernel_addr.as_mut_ptr::<u64>()) = self.offset.as_u64() + entry.get_addend();
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
