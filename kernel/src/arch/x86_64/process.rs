use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr;

use alloc::vec::Vec;

use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

use crate::error::KError;
use crate::kcb::Kcb;
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::{paddr_to_kernel_vaddr, KernelAllocator, PAddr, PhysicalPageProvider, VAddr};
use crate::process::Process;
use crate::round_up;

use super::kcb::Arch86Kcb;
use super::vspace::*;

pub struct UserPtr<T> {
    value: *mut T,
}

impl<T> UserPtr<T> {
    pub fn new(pointer: *mut T) -> UserPtr<T> {
        UserPtr { value: pointer }
    }

    pub fn vaddr(&self) -> VAddr {
        VAddr::from(self.value as u64)
    }
}

impl<T> Deref for UserPtr<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe {
            rflags::stac();
            &*self.value
        }
    }
}

impl<T> DerefMut for UserPtr<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe {
            rflags::stac();
            &mut *self.value
        }
    }
}

impl<T> Drop for UserPtr<T> {
    fn drop(&mut self) {
        unsafe { rflags::clac() };
    }
}

pub struct UserValue<T> {
    value: T,
}

impl<T> UserValue<T> {
    pub fn new(pointer: T) -> UserValue<T> {
        UserValue { value: pointer }
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        unsafe { core::mem::transmute(&self.value) }
    }
}

impl<T> Deref for UserValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            rflags::stac();
            &self.value
        }
    }
}

impl<T> DerefMut for UserValue<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            rflags::stac();
            &mut self.value
        }
    }
}

impl<T> Drop for UserValue<T> {
    fn drop(&mut self) {
        unsafe { rflags::clac() };
    }
}

/// A ResumeHandle that can either be an upcall or a context restore.
///
/// # TODO
/// This two should ideally be separate with a common resume trait once impl Trait
/// is flexible enough.
/// The interface is not really safe at the moment (we use it in very restricted ways
/// i.e., get the handle and immediatle resume but we can def. make this more safe
/// to use...)
pub struct ResumeHandle {
    is_upcall: bool,
    pub save_area: *const kpi::arch::SaveArea,

    entry_point: VAddr,
    stack_top: VAddr,
    cpu_ctl: u64,
    vector: u64,
    exception: u64,
}

impl ResumeHandle {
    pub fn new_restore(save_area: *const kpi::arch::SaveArea) -> ResumeHandle {
        ResumeHandle {
            is_upcall: false,
            save_area: save_area,
            entry_point: VAddr::zero(),
            stack_top: VAddr::zero(),
            cpu_ctl: 0,
            vector: 0,
            exception: 0,
        }
    }

    pub fn new_upcall(
        entry_point: VAddr,
        stack_top: VAddr,
        cpu_ctl: u64,
        vector: u64,
        exception: u64,
    ) -> ResumeHandle {
        ResumeHandle {
            is_upcall: true,
            save_area: ptr::null(),
            entry_point: entry_point,
            stack_top: stack_top,
            cpu_ctl: cpu_ctl,
            vector: vector,
            exception: exception,
        }
    }

    pub unsafe fn resume(self) -> ! {
        if self.is_upcall {
            self.upcall()
        } else {
            self.restore()
        }
    }

    unsafe fn restore(self) -> ! {
        let user_rflags = rflags::RFlags::from_priv(x86::Ring::Ring3)
            | rflags::RFlags::FLAGS_A1
            | rflags::RFlags::FLAGS_IF;

        //info!("resuming User-space with ctxt: {:?}", (*(self.save_area)),);

        // Resumes a process
        // This routine assumes the following set-up
        // %rdi points to SaveArea
        // r11 has rflags
        asm!("  // Restore CPU registers
                movq  0*8(%rdi), %rax
                movq  1*8(%rdi), %rbx
                // %rcx: Don't restore it will contain user-space rip
                movq  3*8(%rdi), %rdx
                // %rdi and %rsi: Restore last (see below) to preserve `save_area`
                movq  6*8(%rdi), %rbp
                movq  7*8(%rdi), %rsp
                movq  8*8(%rdi), %r8
                movq  9*8(%rdi), %r9
                movq 10*8(%rdi), %r10
                // %r11: Don't restore it will contain RFlags
                movq 12*8(%rdi), %r12
                movq 13*8(%rdi), %r13
                movq 14*8(%rdi), %r14
                movq 15*8(%rdi), %r15

                // Restore fs and gs registers
                swapgs
                movq 19*8(%rdi), %rsi
                wrfsbase %rsi

                // Restore vector registers
                fxrstor 24*8(%rdi)

                // sysretq expects user-space %rip in %rcx
                movq 16*8(%rdi),%rcx
                // sysretq expects rflags in %r11
                //movq 17*8(%rdi),%r11

                // At last, restore %rsi and %rdi before we return
                movq  4*8(%rdi), %rsi
                movq  5*8(%rdi), %rdi

                // Let's do sysretq instead of iretq (slow, measure?)
                // (TODO: we need to be more careful about CVE-2012-0217)
                sysretq
            " ::
            "{r11}" (user_rflags.bits())
            "{rdi}" (self.save_area));

        unreachable!("We should not come here!");
    }

    unsafe fn upcall(self) -> ! {
        trace!("About to go to user-space: {:#x}", self.entry_point);
        // TODO: For now we allow unconditional IO access from user-space
        let user_flags =
            rflags::RFlags::FLAGS_IOPL3 | rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF;

        // Switch to user-space with initial zeroed registers.
        //
        // Stack is set to the initial stack for the process that
        // was allocated by the kernel.
        //
        // `sysretq` expectations are:
        // %rcx Program entry point in Ring 3
        // %r11 RFlags
        trace!("Jumping to {:#x}", self.entry_point);
        asm!("
                movq       $0, %rax
                movq       $0, %rbx
                // rcx has entry point
                // rdi: 1st argument
                // rsi: 2nd argument
                // rdx: 3rd argument
                // rsp and rbp are set to provided `stack_top`
                movq       $0, %r8
                movq       $0, %r9
                movq       $0, %r10
                // r11 register is used for RFlags
                movq       $0, %r12
                movq       $0, %r13
                movq       $0, %r14
                movq       $0, %r15

                // Reset vector registers
                fninit

                swapgs
                // TODO: restore fs register

                sysretq
            " ::
            "{rcx}" (self.entry_point.as_u64())
            "{rdi}" (self.cpu_ctl)
            "{rsi}" (self.vector)
            "{rdx}" (self.exception)
            "{r11}" (user_flags.bits())
            "{rsp}" (self.stack_top.as_u64())
            "{rbp}" (self.stack_top.as_u64())
        );

        unreachable!("We should not come here!");
    }
}

/// A process representation.
#[repr(C, packed)]
pub struct Ring3Process {
    /// CPU context save area (must be first, see exec.S).
    pub save_area: kpi::x86_64::SaveArea,
    /// ELF File mappings that were installed into the address space.
    pub mapping: Vec<(VAddr, usize, u64, MapAction)>,
    /// Ring3Process ID.
    pub pid: u64,
    /// The address space of the process.
    pub vspace: VSpace,
    /// Offset where ELF is located.
    pub offset: VAddr,
    /// The entry point of the ELF file.
    pub entry_point: VAddr,

    // TODO: The stuff that comes next is actually per core
    // so we should take it out of here and move it into
    // a separate dispatcher object:
    /// Initial allocated stack (base address).
    pub stack_base: VAddr,
    /// Initial allocated stack (top address).
    pub stack_top: VAddr,
    /// Initial allocated stack size.
    pub stack_size: usize,

    /// Upcall allocated stack (base address).
    pub upcall_stack_base: VAddr,
    /// Upcall allocated stack (top address).
    pub upcall_stack_top: VAddr,
    /// Upcall allocated stack size.
    pub upcall_stack_size: usize,

    /// Virtual CPU control used by the user-space upcall mechanism.
    pub vcpu_ctl: Option<UserPtr<kpi::arch::VirtualCpu>>,
}

impl Ring3Process {
    /// Create a process from a Module (i.e., a struct passed by UEFI)
    pub fn from(module: super::Module) -> Result<Ring3Process, KError> {
        let mut p = Ring3Process::new(0);

        // Load the Module into the process address-space
        // Safe since we don't modify the kernel page-table
        unsafe {
            let e = elfloader::ElfBinary::new(module.name(), module.as_slice())?;
            p.entry_point = VAddr::from(e.entry_point());
            e.load(&mut p)?;
        }

        // Allocate a stack
        // TODO(broken): Use map_frame!
        p.vspace
            .map(
                p.stack_base,
                p.stack_size,
                MapAction::ReadWriteExecuteUser,
                BASE_PAGE_SIZE as u64,
            )
            .expect("Can't map user-space stack");

        info!(
            "stack base {:#x} size: {} end {:#x}",
            p.stack_base,
            p.stack_size,
            p.stack_base + p.stack_size
        );

        // Allocate an upcall stack
        // TODO(broken): Use map_frame!
        p.vspace
            .map(
                p.upcall_stack_base,
                p.upcall_stack_size,
                MapAction::ReadWriteExecuteUser,
                BASE_PAGE_SIZE as u64,
            )
            .expect("Can't map user-space upcall stack.");

        // TODO: make sure we have APIC base (these should be part of kernel
        // mappings and above KERNEL_BASE), should not be hardcoded
        p.vspace.map_identity(
            PAddr(0xfee00000u64),
            PAddr(0xfee00000u64 + BASE_PAGE_SIZE as u64),
            MapAction::ReadWriteExecuteKernel,
        );

        // TODO: Install the kernel mappings (these should be global mappings)
        // TODO(broken): BigMap allocaitons should be inserted here too..
        // TODO(broken): Find a better way for this

        super::kcb::try_get_kcb().map(|kcb: &mut Kcb<Arch86Kcb>| {
            let kernel_pml_entry = kcb.arch.init_vspace().pml4[128];
            trace!("Patched in kernel mappings at {:?}", kernel_pml_entry);
            p.vspace.pml4[128] = kernel_pml_entry;
        });

        Ok(p)
    }

    /// Create a new `empty` process.
    fn new<'b>(pid: u64) -> Ring3Process {
        // TODO: stack_base address should not be hard-coded
        let stack_base = VAddr::from(0xadf000_0000usize);
        let stack_size = 128 * BASE_PAGE_SIZE;
        let stack_top = stack_base + stack_size - 8usize; // -8 due to x86 stack alignemnt requirements

        // TODO: upcall stack address should not be hard-coded
        let upcall_stack_base = VAddr::from(0xad2000_0000usize);
        let upcall_stack_size = 128 * BASE_PAGE_SIZE;
        let upcall_stack_top = upcall_stack_base + stack_size - 8usize; // -8 due to x86 stack alignemnt requirements

        Ring3Process {
            offset: VAddr::from(0usize),
            mapping: Vec::with_capacity(64),
            pid: pid,
            vspace: VSpace::new(),
            save_area: Default::default(),
            entry_point: VAddr::from(0usize),
            stack_base: stack_base,
            stack_top: stack_top,
            stack_size: stack_size,
            upcall_stack_base: upcall_stack_base,
            upcall_stack_size: upcall_stack_size,
            upcall_stack_top: upcall_stack_top,
            vcpu_ctl: None,
        }
    }

    /// Start the process (run it for the first time).
    pub fn start(&mut self) -> ResumeHandle {
        self.maybe_switch_vspace();
        ResumeHandle::new_upcall(self.offset + self.entry_point, self.stack_top, 0, 0, 0)
    }

    pub fn resume(&self) -> ResumeHandle {
        self.maybe_switch_vspace();
        ResumeHandle::new_restore(&self.save_area as *const kpi::arch::SaveArea)
    }

    pub fn upcall(&mut self, vector: u64, exception: u64) -> ResumeHandle {
        self.maybe_switch_vspace();
        let (entry_point, cpu_ctl) = self.vcpu_ctl.as_mut().map_or((VAddr::zero(), 0), |ctl| {
            (ctl.resume_with_upcall, ctl.vaddr().into())
        });

        ResumeHandle::new_upcall(
            entry_point,
            self.upcall_stack_top,
            cpu_ctl,
            vector,
            exception,
        )
    }

    fn maybe_switch_vspace(&self) {
        unsafe {
            let current_pml4 = PAddr::from(controlregs::cr3());
            let process_pml4 = self.vspace.pml4_address();
            if current_pml4 != process_pml4 {
                trace!("Switching to 0x{:x}", process_pml4);
                controlregs::cr3_write(process_pml4.into());
            }
        }
    }
}

impl fmt::Debug for Ring3Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ring3Process {}:\nSaveArea: {:?}",
            self.pid, self.save_area
        )
    }
}

impl elfloader::ElfLoader for Ring3Process {
    /// Makes sure the process' vspace is backed for the regions
    /// reported by the ELF loader as loadable.
    ///
    /// Our strategy is to first figure out how much space we need,
    /// then allocate a single chunk of physical memory and
    /// map the individual pieces of it with different access rights.
    /// This has the advantage that our address space is
    /// all a very simple 1:1 mapping of physical memory.
    fn allocate(&mut self, load_headers: elfloader::LoadableHeaders) -> Result<(), &'static str> {
        for header in load_headers.into_iter() {
            let base = header.virtual_addr();
            let size = header.mem_size() as usize;
            let align_to = header.align();
            let flags = header.flags();

            // Calculate the offset and align to page boundaries
            // We can't expect to get something that is page-aligned from ELF
            let page_mask = (LARGE_PAGE_SIZE - 1) as u64;
            let page_base: VAddr = VAddr::from(base & !page_mask); // Round down to nearest page-size
            let size_page = round_up!(size + (base & page_mask) as usize, LARGE_PAGE_SIZE as usize);
            assert!(size_page >= size);
            assert_eq!(size_page % LARGE_PAGE_SIZE, 0);
            assert_eq!(page_base % LARGE_PAGE_SIZE, 0);

            info!(
                "ELF Allocate: {:#x} -- {:#x} align to {:#x} with flags {:?}",
                page_base,
                page_base + size_page,
                align_to,
                flags,
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

            let large_pages = size_page / LARGE_PAGE_SIZE;

            debug!("page_base {} lps: {}", page_base, large_pages);

            // TODO(correctness): add 20 as estimate of worst case pt requirements
            KernelAllocator::try_refill_tcache(20, large_pages).expect("Refill didn't work");
            self.offset = VAddr::from(0x1000_0000);

            let kcb = crate::kcb::get_kcb();
            let mut pmanager = kcb.mem_manager();

            // TODO(correctness): Will this work (we round-up and map large-pages?)
            // TODO(efficiency): What about wasted memory
            for i in 0..large_pages {
                let frame = pmanager
                    .allocate_large_page()
                    .expect("We refilled so allocation should work.");
                debug!(
                    "process load vspace from {:#x} with {:?}",
                    self.offset + page_base,
                    frame
                );

                self.vspace
                    .map_frame(
                        self.offset + page_base + i * LARGE_PAGE_SIZE,
                        frame,
                        map_action,
                        &mut *pmanager,
                    )
                    .expect("Can't map ELF region");
            }

            // We don't allocate yet -- just record the allocation parameters
            // This has the advantage that we know how much memory we need
            // and can reserve one consecutive chunk of physical memory
            self.mapping
                .push((page_base, size_page, align_to, map_action));
        }

        info!(
            "Binary loaded at address: {:#x} entry {:#x}",
            self.offset, self.entry_point
        );

        Ok(())
    }

    /// Load a region of bytes into the virtual address space of the process.
    fn load(&mut self, destination: u64, region: &[u8]) -> Result<(), &'static str> {
        let destination = self.offset + destination;
        trace!(
            "ELF Load at {:#x} -- {:#x}",
            destination,
            destination + region.len()
        );

        // Load the region at destination in the kernel space
        for (idx, val) in region.iter().enumerate() {
            let vaddr = VAddr::from(destination + idx);
            let paddr = self.vspace.resolve_addr(vaddr);
            if paddr.is_some() {
                // TODO(perf): Inefficient byte-wise copy
                // also within a 4 KiB / 2 MiB page we don't have to resolve_addr
                // every time
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

    /// Relocating the symbols.
    ///
    /// Since the binary is a position independent executable that is 'statically' linked
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
        let kernel_addr: VAddr = paddr_to_kernel_vaddr(paddr);

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

impl Process for Ring3Process {}
