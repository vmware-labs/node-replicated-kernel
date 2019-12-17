#![allow(warnings)]

use alloc::boxed::Box;
use alloc::collections::TryReserveError;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr;

use alloc::vec::Vec;

use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

use crate::kcb::Kcb;
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::{
    paddr_to_kernel_vaddr, Frame, KernelAllocator, PAddr, PhysicalPageProvider, VAddr,
};
use crate::process::{Eid, Executor, Pid, Process, ProcessError, ResumeHandle};
use crate::round_up;

use super::kcb::Arch86Kcb;
use super::vspace::*;
use super::Module;

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

/// A Ring3Resumer that can either be an upcall or a context restore.
///
/// # TODO
/// This two should ideally be separate with a common resume trait once impl Trait
/// is flexible enough.
/// The interface is not really safe at the moment (we use it in very restricted ways
/// i.e., get the handle and immediatle resume but we can def. make this more safe
/// to use...)
pub struct Ring3Resumer {
    is_upcall: bool,
    pub save_area: *const kpi::arch::SaveArea,

    entry_point: VAddr,
    stack_top: VAddr,
    cpu_ctl: u64,
    vector: u64,
    exception: u64,
}

impl ResumeHandle for Ring3Resumer {
    unsafe fn resume(self) {
        unimplemented!()
    }
}

impl Ring3Resumer {
    pub fn new_restore(save_area: *const kpi::arch::SaveArea) -> Ring3Resumer {
        Ring3Resumer {
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
    ) -> Ring3Resumer {
        Ring3Resumer {
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

/// An executor is a thread running in a ring 3 in the context
/// (address-space) of a specific process.
///
/// # Notes
/// repr(C): Because `save_area` in is struct is written to from assembly
/// (and therefore should be first).
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Ring3Executor {
    /// CPU context save area (must be first, see exec.S).
    pub save_area: kpi::x86_64::SaveArea,

    /// Allocated stack (base address).
    pub stack_base: VAddr,

    /// Up-call stack (base address).
    pub upcall_stack_base: VAddr,

    /// Process identifier
    pub pid: Pid,

    /// Executor Identifier
    pub eid: Eid,

    /// Memory affinity of the Executor
    pub affinity: topology::NodeId,

    /// Virtual CPU control used by the user-space upcall mechanism.
    pub vcpu_ctl: VAddr,

    /// Entry point where the executor should start executing from
    ///
    /// Usually ELF start point (for the first dispatcher) then somthing set by process
    /// after.
    ///
    /// e.g. in process this can be computed as self.offset + self.entry_point
    pub entry_point: VAddr,

    /// A handle to the vspace PML4 entry point.
    pub pml4: PAddr,
}

impl Ring3Executor {
    /// Size of the init stack (i.e., initial stack when the dispatcher starts running).
    const INIT_STACK_SIZE: usize = 24 * BASE_PAGE_SIZE;
    /// Size of the upcall signal stack for the dispatcher.
    const UPCALL_STACK_SIZE: usize = 24 * BASE_PAGE_SIZE;

    fn new(
        process: &Ring3Process,
        eid: Eid,
        region: (VAddr, VAddr),
        affinity: topology::NodeId,
    ) -> Self {
        let (from, to) = region;
        assert!(to > from, "Malformed region");
        assert!(
            (to - from).as_usize()
                >= Ring3Executor::INIT_STACK_SIZE
                    + Ring3Executor::UPCALL_STACK_SIZE
                    + core::mem::size_of::<kpi::arch::VirtualCpu>(),
            "Virtual region not big enough"
        );

        let stack_base = from;
        let upcall_stack_base = from + Ring3Executor::INIT_STACK_SIZE;

        let vcpu_vaddr: VAddr =
            from + Ring3Executor::INIT_STACK_SIZE + Ring3Executor::UPCALL_STACK_SIZE;

        Ring3Executor {
            stack_base,
            upcall_stack_base,
            pid: process.pid,
            eid,
            affinity,
            vcpu_ctl: vcpu_vaddr,
            save_area: Default::default(),
            entry_point: process.offset + process.entry_point,
            pml4: process.vspace.pml4_address(),
        }
    }

    pub fn vcpu(&self) -> UserPtr<kpi::arch::VirtualCpu> {
        UserPtr::new(self.vcpu_ctl.as_mut_ptr())
    }

    pub fn vcpu_addr(&self) -> VAddr {
        self.vcpu_ctl
    }

    fn stack_top(&self) -> VAddr {
        // -8 due to x86 stack alignemnt requirements
        self.stack_base + Ring3Executor::INIT_STACK_SIZE - 8usize
    }

    fn upcall_stack_top(&self) -> VAddr {
        // -8 due to x86 stack alignemnt requirements
        self.upcall_stack_base + Ring3Executor::UPCALL_STACK_SIZE - 8usize
    }
}

impl Executor for Ring3Executor {
    type Resumer = Ring3Resumer;

    /// Start the process (run it for the first time).
    fn start(&mut self) -> Ring3Resumer {
        self.maybe_switch_vspace();
        Ring3Resumer::new_upcall(self.entry_point, self.stack_top(), 0, 0, 0)
    }

    fn resume(&self) -> Ring3Resumer {
        self.maybe_switch_vspace();
        Ring3Resumer::new_restore(&self.save_area as *const kpi::arch::SaveArea)
    }

    fn upcall(&mut self, vector: u64, exception: u64) -> Ring3Resumer {
        self.maybe_switch_vspace();
        let entry_point = self.vcpu().resume_with_upcall;
        let cpu_ctl = self.vcpu().vaddr().as_u64();

        Ring3Resumer::new_upcall(
            entry_point,
            self.upcall_stack_top(),
            cpu_ctl,
            vector,
            exception,
        )
    }

    fn maybe_switch_vspace(&self) {
        unsafe {
            let current_pml4 = PAddr::from(controlregs::cr3());
            if current_pml4 != self.pml4 {
                trace!("Switching to 0x{:x}", self.pml4);
                controlregs::cr3_write(self.pml4.into());
            }
        }
    }
}

/// A process representation.
pub struct Ring3Process {
    /// Ring3Process ID.
    pub pid: Pid,
    /// Ring3Executor ID.
    pub current_eid: Eid,
    /// The address space of the process.
    pub vspace: VSpace,
    /// Offset where ELF is located.
    pub offset: VAddr,
    /// The entry point of the ELF file (set during elfloading).
    pub entry_point: VAddr,
    /// Executor cache (holds a per-region cache of executors)
    pub executor_cache:
        arrayvec::ArrayVec<[Option<Vec<Box<Ring3Executor>>>; super::MAX_NUMA_NODES]>,
    /// Offset where executor memory is located in user-space.
    pub executor_offset: VAddr,
}

impl Ring3Process {
    fn create(pid: Pid) -> Self {
        let mut executor_cache: arrayvec::ArrayVec<
            [Option<Vec<Box<Ring3Executor>>>; super::MAX_NUMA_NODES],
        > = Default::default();
        for _i in 0..super::MAX_NUMA_NODES {
            executor_cache.push(None);
        }

        Ring3Process {
            pid,
            offset: VAddr::from(0x20_0000_0000usize),
            current_eid: 0,
            vspace: VSpace::new(),
            entry_point: VAddr::from(0usize),
            executor_cache,
            executor_offset: VAddr::from(0x21_0000_0000usize),
        }
    }
}

impl fmt::Debug for Ring3Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ring3Process {}", self.pid)
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
            let (paddr, _rights) = self
                .vspace
                .resolve(vaddr)
                .map_err(|_e| "Can't write to the resolved address in the kernel vspace.")?;

            // TODO(perf): Inefficient byte-wise copy
            // also within a 4 KiB / 2 MiB page we don't have to resolve_addr
            // every time
            let ptr = paddr.as_u64() as *mut u8;
            unsafe {
                *ptr = *val;
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
        let (paddr, _rights) = self.vspace.resolve(addr).expect("Can't resolve address");
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

impl Process for Ring3Process {
    type E = Ring3Executor;
    type A = VSpace;

    /// Create a process from a module
    fn new(module: &Module, pid: Pid) -> Result<Ring3Process, ProcessError> {
        let mut p = Ring3Process::create(pid);

        // Load the Module into the process address-space
        // This needs mostly sanitation work on elfloader and
        // ElfLoad trait impl for process to be safe
        unsafe {
            let e = elfloader::ElfBinary::new(module.name(), module.as_slice())?;
            p.entry_point = VAddr::from(e.entry_point());
            e.load(&mut p)?;
        }

        // Install the kernel mappings
        // TODO(efficiency): These should probably be global mappings
        // TODO(broken): Big (>= 2 MiB) allocations should be inserted here too
        // TODO(ugly): Find a better way to express this mess
        super::kcb::try_get_kcb().map(|kcb: &mut Kcb<Arch86Kcb>| {
            let mut pmanager = kcb.mem_manager();

            // TODO: make sure we have APIC base (these should be part of kernel
            // mappings and above KERNEL_BASE), should not be hardcoded
            p.vspace
                .map_identity(
                    PAddr(0xfee00000u64),
                    BASE_PAGE_SIZE,
                    MapAction::ReadWriteExecuteKernel,
                    &mut *pmanager,
                )
                .expect("Can't map APIC");

            let kernel_pml_entry = kcb.arch.init_vspace().pml4[128];
            trace!("Patched in kernel mappings at {:?}", kernel_pml_entry);
            p.vspace.pml4[128] = kernel_pml_entry;
        });

        Ok(p)
    }

    fn try_reserve_executors(
        &self,
        how_many: usize,
        affinity: topology::NodeId,
    ) -> Result<(), TryReserveError> {
        // TODO(correctness): Lacking impl
        Ok(())
    }

    fn vspace(&mut self) -> &mut VSpace {
        &mut self.vspace
    }

    fn get_executor(
        &mut self,
        for_region: topology::NodeId,
    ) -> Result<Box<Ring3Executor>, ProcessError> {
        info!("get executor {}", for_region);
        match &mut self.executor_cache[for_region as usize] {
            Some(ref mut executor_list) => {
                let ret = executor_list.pop().ok_or(ProcessError::NoExecutorAllocated);
                info!("executor list {:?}", ret);
                ret
            }
            None => Err(ProcessError::NoExecutorAllocated),
        }
    }

    /// Create a series of dispatcher objects for the process
    fn allocate_executors(&mut self, memory: Frame) -> Result<(), ProcessError> {
        KernelAllocator::try_refill_tcache(20, 0).expect("Refill didn't work");
        {
            let kcb = crate::kcb::get_kcb();
            let mut pmanager = kcb.mem_manager();

            self.vspace
                .map_frame(
                    self.executor_offset,
                    memory,
                    MapAction::ReadWriteUser,
                    &mut *pmanager,
                )
                .expect("Can't map user-space executor memory.");

            debug!(
                "executor space base expanded {:#x} size: {} end {:#x}",
                self.executor_offset,
                memory.size(),
                self.executor_offset + memory.size()
            );
        }

        let executor_space_requirement =
            Ring3Executor::INIT_STACK_SIZE + Ring3Executor::UPCALL_STACK_SIZE + BASE_PAGE_SIZE;
        let executors_to_create = memory.size() / executor_space_requirement;

        let cur_offset = self.executor_offset;
        for cnt in 0..executors_to_create {
            let executor_vmem_start = cur_offset;
            let executor_vmem_end = executor_vmem_start + executor_space_requirement;

            let upcall_stack_base = cur_offset + Ring3Executor::INIT_STACK_SIZE;
            let vcpu_ctl =
                cur_offset + Ring3Executor::INIT_STACK_SIZE + Ring3Executor::UPCALL_STACK_SIZE;

            let executor = Box::new(Ring3Executor::new(
                &self,
                self.current_eid,
                (executor_vmem_start, executor_vmem_end),
                memory.affinity,
            ));

            use alloc::vec;
            match &mut self.executor_cache[memory.affinity as usize] {
                Some(ref mut vector) => vector.push(executor),
                None => self.executor_cache[memory.affinity as usize] = Some(vec![executor]),
            }

            self.current_eid + 1;
        }

        debug!(
            "created allocators in {:#x} -- {:#x}",
            self.executor_offset,
            self.executor_offset + memory.size()
        );

        self.executor_offset += memory.size();
        Ok(())
    }
}
