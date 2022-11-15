// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::collections::TryReserveError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::arch::asm;
use core::cell::RefCell;
use core::cmp::PartialEq;
use core::{fmt, ptr};
use fallible_collections::try_vec;
use fallible_collections::FallibleVec;
use kpi::arch::SaveArea;
use kpi::arch::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use lazy_static::lazy_static;

use crate::arch::kcb::per_core_mem;
use crate::error::KResult;
use crate::fs::{fd::FileDescriptorEntry, MAX_FILES_PER_PROCESS};
use crate::memory::detmem::DA;
use crate::memory::paddr_to_kernel_vaddr;
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::KernelAllocator;
use crate::memory::{Frame, MemType, PAddr, VAddr};
use crate::nrproc::NrProcess;
use crate::prelude::KError;
use crate::process::{
    Eid, Executor, Pid, Process, ResumeHandle, MAX_FRAMES_PER_PROCESS, MAX_PROCESSES,
    MAX_WRITEABLE_SECTIONS_PER_PROCESS,
};
use kpi::process::{FrameId, ELF_OFFSET, EXECUTOR_OFFSET};
use node_replication::{Dispatch, Log, Replica};

use cortex_a::{asm::barrier, registers::*};
use tock_registers::{
    interfaces::{Readable, Writeable},
    registers::InMemoryRegister,
};

use super::vspace::*;
use super::Module;
use super::MAX_NUMA_NODES;
use crate::round_up;

/// the architecture specific stack alignment for processes
pub(crate) const STACK_ALIGNMENT: usize = 16;

/// The process model of the current architecture.
pub(crate) type ArchProcess = EL0Process;

///The executor of the current architecture.
pub(crate) type ArchExecutor = EL0Executor;

///The resumer of the current architecture.
pub(crate) type ArchResumer = EL0Resumer;

pub(crate) struct EL0Process {
    /// EL0 Process ID.
    pub pid: Pid,
    /// EL0Executor ID.
    pub current_eid: Eid,
    /// The address space of the process.
    pub vspace: VSpace,
    /// Offset where ELF is located.
    pub offset: VAddr,
    /// Process info struct (can be retrieved by user-space)
    pub pinfo: kpi::process::ProcessInfo,
    /// The entry point of the ELF file (set during elfloading).
    pub entry_point: VAddr,
    /// Executor cache (holds a per-region cache of executors)
    pub executor_cache: ArrayVec<Option<Vec<Box<ArchExecutor>>>, MAX_NUMA_NODES>,
    /// Offset where executor memory is located in user-space.
    pub executor_offset: VAddr,
    /// File descriptors for the opened file.
    pub fds: ArrayVec<Option<FileDescriptorEntry>, MAX_FILES_PER_PROCESS>,
    /// Physical frame objects registered to the process.
    pub frames: ArrayVec<Option<Frame>, MAX_FRAMES_PER_PROCESS>,
    /// Frames of the writeable ELF data section (shared across all replicated Process structs)
    pub writeable_sections: ArrayVec<Frame, MAX_WRITEABLE_SECTIONS_PER_PROCESS>,
    /// Section in ELF where last read-only header is
    ///
    /// (TODO(robustness): assumes that all read-only segments come before
    /// writable segments).
    pub read_only_offset: VAddr,
}

impl EL0Process {
    fn new(pid: Pid, da: DA) -> Result<Self, KError> {
        const NONE_EXECUTOR: Option<Vec<Box<ArchExecutor>>> = None;
        let executor_cache: ArrayVec<Option<Vec<Box<ArchExecutor>>>, MAX_NUMA_NODES> =
            ArrayVec::from([NONE_EXECUTOR; MAX_NUMA_NODES]);

        const NONE_FD: Option<FileDescriptorEntry> = None;
        let fds: ArrayVec<Option<FileDescriptorEntry>, MAX_FILES_PER_PROCESS> =
            ArrayVec::from([NONE_FD; MAX_FILES_PER_PROCESS]);

        let frames: ArrayVec<Option<Frame>, MAX_FRAMES_PER_PROCESS> =
            ArrayVec::from([None; MAX_FRAMES_PER_PROCESS]);

        Ok(Self {
            pid,
            current_eid: 0,
            offset: VAddr::from(ELF_OFFSET),
            vspace: VSpace::new(da)?,
            entry_point: VAddr::from(0usize),
            executor_cache,
            executor_offset: VAddr::from(EXECUTOR_OFFSET),
            fds,
            pinfo: Default::default(),
            frames,
            writeable_sections: ArrayVec::new(),
            read_only_offset: VAddr::zero(),
        })
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
pub struct EL0Executor {
    /// CPU context save area (must be first, see exec.S).
    pub save_area: SaveArea,

    /// Allocated stack (base address).
    pub stack_base: VAddr,

    /// Up-call stack (base address).
    pub upcall_stack_base: VAddr,

    /// Process identifier
    pub pid: Pid,

    /// Executor Identifier
    pub eid: Eid,

    /// Memory affinity of the Executor
    pub affinity: atopology::NodeId,

    /// Virtual CPU control used by the user-space upcall mechanism.
    pub vcpu_ctl: VAddr,

    /// Alias to `vcpu_ctl` but accessible in kernel space.
    pub vcpu_ctl_kernel: VAddr,

    /// Entry point where the executor should start executing from
    ///
    /// Usually an ELF start point (for the first dispatcher) then somthing set
    /// by the process after.
    ///
    /// e.g. in process this can be computed as self.offset + self.entry_point
    pub entry_point: VAddr,

    /// A handle to the vspace PML4 entry point.
    pub vroot: PAddr,
}

impl EL0Executor {
    /// Size of the init stack (i.e., initial stack when the dispatcher starts running).
    const INIT_STACK_SIZE: usize = 24 * BASE_PAGE_SIZE;
    /// Size of the upcall signal stack for the dispatcher.
    const UPCALL_STACK_SIZE: usize = 24 * BASE_PAGE_SIZE;
    /// Total memory consumption (in a process' vspace) that the executor uses.
    /// (2 stacks plus the VirtualCpu struct.)
    const EXECUTOR_SPACE_REQUIREMENT: usize =
        EL0Executor::INIT_STACK_SIZE + EL0Executor::UPCALL_STACK_SIZE + BASE_PAGE_SIZE;

    fn new(
        process: &EL0Process,
        eid: Eid,
        vcpu_ctl_kernel: VAddr,
        region: (VAddr, VAddr),
        affinity: atopology::NodeId,
    ) -> Self {
        let (from, to) = region;
        assert!(to > from, "Malformed region");
        assert!(
            (to - from).as_usize()
                >= EL0Executor::INIT_STACK_SIZE
                    + EL0Executor::UPCALL_STACK_SIZE
                    + core::mem::size_of::<kpi::arch::VirtualCpu>(),
            "Virtual region not big enough"
        );

        let stack_base = from;
        let upcall_stack_base = from + EL0Executor::INIT_STACK_SIZE;

        let vcpu_vaddr: VAddr =
            from + EL0Executor::INIT_STACK_SIZE + EL0Executor::UPCALL_STACK_SIZE;

        EL0Executor {
            stack_base,
            upcall_stack_base,
            pid: process.pid,
            eid,
            affinity,
            vcpu_ctl_kernel,
            vcpu_ctl: vcpu_vaddr,
            save_area: Default::default(),
            entry_point: process.offset + process.entry_point,
            // Note: The PML4 is a bit awkward here, we must ensure to use the
            // PML4 of the local replica, but aside from some asserts in
            // `start`, `resume` etc. nothing prevents us from running this
            // executor on a different replica (which means the advance log on
            // pfault would not really advance the right set of page-tables)
            vroot: process.vspace.root_table_address(),
        }
    }

    /// Get access to the executors' vcpu area.
    ///
    /// # Safety
    /// - Caller needs to ensure it doesn't accidentially create two mutable
    ///   aliasable pointers to the same memory.
    /// - TODO(api): A safer API for this might be appreciated.
    pub(crate) fn vcpu(&self) -> &mut kpi::arch::VirtualCpu {
        unsafe { &mut *self.vcpu_ctl_kernel.as_mut_ptr() }
    }

    pub(crate) fn vcpu_addr(&self) -> VAddr {
        self.vcpu_ctl
    }

    fn stack_top(&self) -> VAddr {
        // -16 due to AArch64 stack alignemnt requirements
        self.stack_base + EL0Executor::INIT_STACK_SIZE - 16usize
    }

    fn upcall_stack_top(&self) -> VAddr {
        // -16 due to AArch64 stack alignemnt requirements
        self.upcall_stack_base + EL0Executor::UPCALL_STACK_SIZE - 16usize
    }
}

impl fmt::Display for EL0Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EL0Executor {}", self.eid)
    }
}

impl PartialEq<EL0Executor> for EL0Executor {
    fn eq(&self, other: &EL0Executor) -> bool {
        self.pid == other.pid && self.eid == other.eid
    }
}

/// A handle to the currently active (scheduled on the core) process.
#[thread_local]
pub(crate) static CURRENT_EXECUTOR: RefCell<Option<Box<ArchExecutor>>> = RefCell::new(None);

/// Swaps out current process with a new process. Returns the old process.
pub(crate) fn swap_current_executor(new_executor: Box<ArchExecutor>) -> Option<Box<ArchExecutor>> {
    CURRENT_EXECUTOR.borrow_mut().replace(new_executor)
}

pub(crate) fn has_executor() -> bool {
    CURRENT_EXECUTOR.borrow().is_some()
}

pub(crate) fn current_pid() -> KResult<Pid> {
    Ok(CURRENT_EXECUTOR
        .borrow()
        .as_ref()
        .ok_or(KError::ProcessNotSet)?
        .pid)
}

lazy_static! {
    pub(crate) static ref PROCESS_TABLE: ArrayVec<ArrayVec<Arc<Replica<'static, NrProcess<ArchProcess>>>, MAX_PROCESSES>, MAX_NUMA_NODES> = {
        // Want at least one replica...
        let numa_nodes = core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes());
        let mut numa_cache = ArrayVec::new();
        for _n in 0..numa_nodes {
            let process_replicas = ArrayVec::new();
            debug_assert!(!numa_cache.is_full());
            numa_cache.push(process_replicas)
        }
        for pid in 0..MAX_PROCESSES {
                let log = Arc::try_new(Log::<<NrProcess<ArchProcess> as Dispatch>::WriteOperation>::new(
                    LARGE_PAGE_SIZE,
                )).expect("Can't initialize processes, out of memory.");

            let da = DA::new().expect("Can't initialize process deterministic memory allocator");
            for node in 0..numa_nodes {

                let pcm = per_core_mem();
                pcm.set_mem_affinity(node as atopology::NodeId).expect("Can't change affinity");
                debug_assert!(!numa_cache[node].is_full());
                let my_da = da.clone();
                let pr = ArchProcess::new(pid, my_da).expect("Can't create process during init");
                let p = Box::try_new(pr).expect("Not enough memory to initialize processes");
                let nrp = NrProcess::new(p, da.clone());
                numa_cache[node].push(Replica::<NrProcess<ArchProcess>>::with_data(&log, nrp));

                debug_assert_eq!(*crate::environment::NODE_ID, 0, "Expect initialization to happen on node 0.");
                pcm.set_mem_affinity(0 as atopology::NodeId).expect("Can't change affinity");
            }
        }

        numa_cache
    };
}

const INVALID_EXECUTOR_START: VAddr = VAddr(0xdeadffff);

/// Spawns a new process
///
/// We're loading a process from a module:
/// - First we are constructing our own custom elfloader trait to load figure out
///   which program headers in the module will be writable (these should not be replicated by NR)
/// - Then we continue by creating a new Process through an nr call
/// - Then we allocate a bunch of memory on all NUMA nodes to create enough dispatchers
///   so we can run on all cores
/// - Finally we allocate a dispatcher to the current core (0) and start running the process
#[cfg(target_os = "none")]
pub(crate) fn spawn(binary: &'static str) -> Result<Pid, KError> {
    use crate::nr;
    use crate::process::{allocate_dispatchers, make_process};

    let pid = make_process::<EL0Process>(binary)?;
    allocate_dispatchers::<EL0Process>(pid)?;

    // Set current thread to run executor from our process (on the current core)
    let _gtid = nr::KernelNode::allocate_core_to_process(
        pid,
        INVALID_EXECUTOR_START, // This VAddr is irrelevant as it is overriden later
        Some(*crate::environment::NODE_ID),
        Some(*crate::environment::CORE_ID),
    )?;

    Ok(pid)
}

pub(crate) struct ArchProcessManagement;

impl crate::nrproc::ProcessManager for ArchProcessManagement {
    type Process = ArchProcess;

    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    > {
        &*super::process::PROCESS_TABLE
    }
}

/// Runs a closure `f` while the current core has access to user-space enabled.
///
/// Access is disabled again after `f` returns.
pub(crate) fn with_user_space_access_enabled<F, R>(f: F) -> KResult<R>
where
    F: FnOnce() -> KResult<R>,
{
    panic!("not yet implemented");
}

/// Resume the state saved in `SaveArea` using the `iretq` instruction.
///
/// # Safety
/// Pretty unsafe low-level API that switches to an arbitrary
/// context/instruction pointer. Caller should make sure that `state` is
/// "valid", meaning is an alive context that has not already been resumed.

pub(crate) struct EL1Resumer {
    pub save_area: *const SaveArea,
}

impl EL1Resumer {
    pub(crate) fn new_iret(save_area: *const SaveArea) -> EL1Resumer {
        EL1Resumer { save_area }
    }
}

impl ResumeHandle for EL1Resumer {
    unsafe fn resume(self) -> ! {
        panic!("not yet implemented");
    }
}

#[derive(Eq, PartialEq, Debug)]
enum ResumeStrategy {
    Start,
    SysRet,
    IRet,
    Upcall,
}

/// A EL0REsumer that can either be an upcall or a context restore.
///
/// # TODO
/// This two should ideally be separate with a common resume trait once impl Trait
/// is flexible enough.
/// The interface is not really safe at the moment (we use it in very restricted ways
/// i.e., get the handle and immediatle resume but we can def. make this more safe
/// to use...)
pub(crate) struct EL0Resumer {
    typ: ResumeStrategy,
    pub save_area: *const kpi::arch::SaveArea,

    entry_point: VAddr,
    stack_top: VAddr,
    cpu_ctl: u64,
    vector: u64,
    exception: u64,
}

impl EL0Resumer {
    pub(crate) fn new_iret(save_area: *const kpi::arch::SaveArea) -> EL0Resumer {
        EL0Resumer {
            typ: ResumeStrategy::IRet,
            save_area: save_area,
            entry_point: VAddr::zero(),
            stack_top: VAddr::zero(),
            cpu_ctl: 0,
            vector: 0,
            exception: 0,
        }
    }

    pub(crate) fn new_restore(save_area: *const kpi::arch::SaveArea) -> EL0Resumer {
        EL0Resumer {
            typ: ResumeStrategy::SysRet,
            save_area: save_area,
            entry_point: VAddr::zero(),
            stack_top: VAddr::zero(),
            cpu_ctl: 0,
            vector: 0,
            exception: 0,
        }
    }

    pub(crate) fn new_upcall(
        entry_point: VAddr,
        stack_top: VAddr,
        cpu_ctl: u64,
        vector: u64,
        exception: u64,
    ) -> EL0Resumer {
        EL0Resumer {
            typ: ResumeStrategy::Upcall,
            save_area: ptr::null(),
            entry_point,
            stack_top,
            cpu_ctl,
            vector,
            exception,
        }
    }

    pub(crate) fn new_start(entry_point: VAddr, stack_top: VAddr) -> EL0Resumer {
        EL0Resumer {
            typ: ResumeStrategy::Start,
            save_area: ptr::null(),
            entry_point,
            stack_top,
            cpu_ctl: 0,
            vector: 0,
            exception: 0,
        }
    }

    unsafe fn iret_restore(self) -> ! {
        panic!("not yet implemented");
    }

    unsafe fn restore(self) -> ! {
        panic!("not yet implemented");
    }

    unsafe fn upcall(self) -> ! {
        log::trace!("About to go to user-space: {:#x}", self.entry_point);
        panic!("not yet implemented");
    }

    unsafe fn start(self) -> ! {
        log::info!("About to go to user-space: {:#x}", self.entry_point);

        // SPSR_EL1::M::EL0t
        asm!("
            msr spsr_el1, x3
            msr elr_el1,  x2
            msr sp_el0,   x1

            eret",
            in("x3")  0x40,
            in("x2") self.entry_point.as_u64(),
            in("x1") self.stack_top.as_u64(),
            options(noreturn)
        );
    }
}

impl ResumeHandle for EL0Resumer {
    unsafe fn resume(self) -> ! {
        match self.typ {
            ResumeStrategy::Start => self.start(),
            ResumeStrategy::Upcall => self.upcall(),
            ResumeStrategy::SysRet => self.restore(),
            ResumeStrategy::IRet => self.iret_restore(),
        }
    }
}

impl elfloader::ElfLoader for ArchProcess {
    /// Makes sure the process' vspace is backed for the regions
    /// reported by the ELF loader as loadable.
    ///
    /// Our strategy is to first figure out how much space we need,
    /// then allocate a single chunk of physical memory and
    /// map the individual pieces of it with different access rights.
    /// This has the advantage that our address space is
    /// all a very simple 1:1 mapping of physical memory.
    fn allocate(
        &mut self,
        load_headers: elfloader::LoadableHeaders,
    ) -> Result<(), elfloader::ElfLoaderErr> {
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

            let map_action = match (flags.is_execute(), flags.is_write(), flags.is_read()) {
                (false, false, false) => panic!("MapAction::None"),
                (true, false, false) => panic!("MapAction::None"),
                (false, true, false) => panic!("MapAction::None"),
                (false, false, true) => MapAction::ReadUser,
                (true, false, true) => MapAction::ReadExecuteUser,
                (true, true, false) => panic!("MapAction::None"),
                (false, true, true) => MapAction::ReadWriteUser,
                (true, true, true) => panic!("MapAction::ReadWriteExecuteUser"), // MapAction::ReadWriteExecuteUser,
            };

            log::info!(
                "ELF Allocate: {:#x} -- {:#x} align to {:#x} with flags {:?} ({:?})",
                page_base,
                page_base + size_page,
                align_to,
                flags,
                map_action
            );

            let large_pages = size_page / LARGE_PAGE_SIZE;
            log::debug!("page_base {} lps: {}", page_base, large_pages);

            // TODO(correctness): add 20 as estimate of worst case pt requirements
            KernelAllocator::try_refill_tcache(20, large_pages, MemType::Mem)
                .expect("Refill didn't work");

            let pcm = crate::arch::kcb::per_core_mem();

            // TODO(correctness): Will this work (we round-up and map large-pages?)
            // TODO(efficiency): What about wasted memory
            // TODO(hard-coded replication assumptions): We assume that we only have 1 data section
            // that is read-write and that fits within data_frame (so replication works out)
            // We should probably return an error and request more bigger data frames if what
            // we provide initially doesn't work out...
            let mut wsection_idx = 0;
            for i in 0..large_pages {
                let frame = if flags.is_write() {
                    // Writeable program-headers we can't replicate:
                    assert!(
                        wsection_idx < self.writeable_sections.len(),
                        "Didn't pass enough frames for writeable sections to process create."
                    );
                    assert_eq!(
                        self.writeable_sections[wsection_idx].size(),
                        LARGE_PAGE_SIZE,
                        "We expect writeable sections frame to be a large-page."
                    );
                    let frame = self.writeable_sections[wsection_idx];
                    wsection_idx += 1;
                    frame
                } else {
                    // A read-only program header we can replicate:
                    assert!(
                        map_action == MapAction::ReadUser
                            || map_action == MapAction::ReadExecuteUser
                    );
                    let mut pmanager = pcm.mem_manager();
                    pmanager
                        .allocate_large_page()
                        .expect("We refilled so allocation should work.")
                };

                log::trace!(
                    "process load vspace from {:#x} with {:?}",
                    self.offset + page_base + i * LARGE_PAGE_SIZE,
                    frame
                );

                self.vspace
                    .map_frame(
                        self.offset + page_base + i * LARGE_PAGE_SIZE,
                        frame,
                        map_action,
                    )
                    .expect("Can't map ELF region");
            }
        }

        log::info!(
            "Binary loaded at address: {:#x} entry {:#x}",
            self.offset,
            self.entry_point
        );

        Ok(())
    }

    /// Load a region of bytes into the virtual address space of the process.
    fn load(
        &mut self,
        flags: elfloader::Flags,
        destination: u64,
        region: &[u8],
    ) -> Result<(), elfloader::ElfLoaderErr> {
        let destination = self.offset + destination;

        // Only write to the read-only sections, writable frames already have
        // the right content (see DataSecLoader in src/process.rs)
        if !flags.is_write() {
            self.read_only_offset = destination + region.len();
            log::info!(
                "ELF Load of read-only region at {:#x} -- {:#x}",
                destination,
                destination + region.len()
            );

            // Load the region at destination in the kernel space
            for (idx, val) in region.iter().enumerate() {
                let vaddr = VAddr::from(destination + idx);
                let (paddr, _rights) = self.vspace.resolve(vaddr).map_err(|_e| {
                    log::error!("resolve error: {:p} {}", vaddr, _e);
                    "Can't write to the resolved address in the kernel vspace."
                })?;

                // TODO(perf): Inefficient byte-wise copy also within a 4 KiB /
                // 2 MiB page we don't have to resolve_addr every time
                if idx == 0 {
                    log::trace!(
                        "write ptr = {:p} vaddr = {:#x} dest+idx={:#x}",
                        paddr,
                        vaddr,
                        destination + idx
                    );
                }

                let ptr: *mut u8 = paddr_to_kernel_vaddr(paddr).as_mut_ptr();
                unsafe {
                    *ptr = *val;
                }
            }
        } else {
            log::debug!(
                "Skip ELF Load of writeable region at {:#x} -- {:#x}",
                destination,
                destination + region.len()
            );
        }

        Ok(())
    }

    /// Relocating the symbols.
    ///
    /// Since the binary is a position independent executable that is 'statically' linked
    /// with all dependencies we only expect to get relocations of type RELATIVE.
    /// Otherwise, the build would be broken or you got a garbage ELF file.
    /// We return an error in this case.
    fn relocate(
        &mut self,
        entry: elfloader::RelocationEntry,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        use elfloader::arch::aarch64::RelocationTypes::R_AARCH64_RELATIVE;
        use elfloader::RelocationType;

        // Get the pointer to where the relocation happens in the
        // memory where we loaded the headers
        // The forumla for this is our offset where the kernel is starting,
        // plus the offset of the entry to jump to the code piece
        let addr = self.offset + entry.offset;

        if addr >= self.read_only_offset {
            // Don't relocate anything in write-able section, already done
            return Ok(());
        }

        // Translate `addr` into a kernel vaddr we can write to:
        let (paddr, _rights) = self.vspace.resolve(addr).expect("Can't resolve address");
        let kernel_addr: VAddr = paddr_to_kernel_vaddr(paddr);

        log::debug!(
            "ELF relocation paddr {:#x} kernel_addr {:#x}",
            paddr,
            kernel_addr
        );

        let addend = entry
            .addend
            .ok_or(elfloader::ElfLoaderErr::UnsupportedRelocationEntry)?;

        match entry.rtype {
            RelocationType::AArch64(R_AARCH64_RELATIVE) => {
                unsafe {
                    // Scary unsafe changing stuff in random memory locations based on
                    // ELF binary values weee!
                    *(kernel_addr.as_mut_ptr::<u64>()) = self.offset.as_u64() + addend;
                }
                Ok(())
            }
            _ => Err(elfloader::ElfLoaderErr::UnsupportedRelocationEntry),
        }
    }

    fn make_readonly(&mut self, base: u64, size: usize) -> Result<(), elfloader::ElfLoaderErr> {
        log::trace!(
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

    fn tls(
        &mut self,
        tdata_start: u64,
        tdata_length: u64,
        total_size: u64,
        align: u64,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        self.pinfo.has_tls = true;
        self.pinfo.tls_data = self.offset.as_u64() + tdata_start;
        self.pinfo.tls_data_len = tdata_length;
        self.pinfo.tls_len_total = total_size;
        self.pinfo.alignment = align;
        Ok(())
    }
}

impl Process for ArchProcess {
    type E = ArchExecutor;
    type A = VSpace;

    /// Return the process ID.
    fn pid(&self) -> Pid {
        self.pid
    }

    fn vspace_mut(&mut self) -> &mut VSpace {
        &mut self.vspace
    }

    fn vspace(&self) -> &VSpace {
        &self.vspace
    }

    fn load(
        &mut self,
        pid: Pid,
        module: &Module,
        writeable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
        log::warn!("{}::{}", module_path!(), line!());

        self.pid = pid;
        // TODO(error-handling): properly unwind on error
        self.writeable_sections.clear();
        for sec in writeable_sections {
            self.writeable_sections.try_push(sec)?;
        }

        // Load the Module into the process address-space
        // This needs mostly sanitation work on elfloader and
        // ElfLoad trait impl for process to be safe
        unsafe {
            let e = elfloader::ElfBinary::new(module.as_slice())?;
            if !e.is_pie() {
                // We don't have an offset for non-pie applications (rump apps)
                self.offset = VAddr::zero();
            }
            self.entry_point = VAddr::from(e.entry_point());
            e.load(self)?;
        }

        Ok(())
    }

    fn try_reserve_executors(
        &self,
        _how_many: usize,
        _affinity: atopology::NodeId,
    ) -> Result<(), TryReserveError> {
        // TODO(correctness): Lacking impl
        Ok(())
    }

    fn get_executor(&mut self, for_region: atopology::NodeId) -> Result<Box<ArchExecutor>, KError> {
        match &mut self.executor_cache[for_region as usize] {
            Some(ref mut executor_list) => {
                let ret = executor_list.pop().ok_or(KError::ExecutorCacheExhausted)?;
                //info!("get executor {} with affinity {}", ret.eid, for_region);
                Ok(ret)
            }
            None => Err(KError::NoExecutorAllocated),
        }
    }

    fn allocate_executors(&mut self, memory: Frame) -> Result<usize, KError> {
        let executor_space_requirement = ArchExecutor::EXECUTOR_SPACE_REQUIREMENT;
        let executors_to_create = memory.size() / executor_space_requirement;

        KernelAllocator::try_refill_tcache(20, 0, MemType::Mem).expect("Refill didn't work");
        self.vspace
            .map_frame(self.executor_offset, memory, MapAction::ReadWriteUser)
            .expect("Can't map user-space executor memory.");
        log::info!(
            "executor space base expanded {:#x} size: {} end {:#x}",
            self.executor_offset,
            memory.size(),
            self.executor_offset + memory.size()
        );

        let executor_space = executor_space_requirement * executors_to_create;
        let prange = memory.base..memory.base + executor_space;
        let vrange = self.executor_offset..self.executor_offset + executor_space;

        for (executor_pmem_start, executor_vmem_start) in prange
            .step_by(executor_space_requirement)
            .zip(vrange.step_by(executor_space_requirement))
        {
            let executor_vmem_end = executor_vmem_start + executor_space_requirement;
            let vcpu_ctl = executor_vmem_start
                + ArchExecutor::INIT_STACK_SIZE
                + ArchExecutor::UPCALL_STACK_SIZE;
            let vcpu_ctl_paddr = executor_pmem_start
                + ArchExecutor::INIT_STACK_SIZE
                + ArchExecutor::UPCALL_STACK_SIZE;
            let vcpu_ctl_kernel = crate::memory::paddr_to_kernel_vaddr(PAddr::from(vcpu_ctl_paddr));
            log::trace!(
                "vcpu_ctl vaddr {:#x} vcpu_ctl paddr {:#x} vcpu_ctl_kernel {:#x}",
                vcpu_ctl,
                vcpu_ctl_paddr,
                vcpu_ctl_kernel
            );

            let executor = Box::try_new(ArchExecutor::new(
                &self,
                self.current_eid,
                vcpu_ctl_kernel,
                (executor_vmem_start, executor_vmem_end),
                memory.affinity,
            ))?;

            log::debug!("Created {} affinity {}", executor, memory.affinity);

            // TODO(error-handling): Needs to properly unwind on alloc errors
            // (e.g., have something that frees vcpu mem etc. on drop())
            match &mut self.executor_cache[memory.affinity as usize] {
                Some(ref mut vector) => vector.try_push(executor)?,
                None => self.executor_cache[memory.affinity as usize] = Some(try_vec![executor]?),
            }

            self.current_eid += 1;
        }

        log::debug!(
            "Created allocators in {:#x} -- {:#x} (we now have {} in total)",
            self.executor_offset,
            self.executor_offset + memory.size(),
            self.current_eid
        );

        self.executor_offset += memory.size();
        Ok(executors_to_create)
    }

    fn allocate_fd(&mut self) -> Option<(u64, &mut FileDescriptorEntry)> {
        if let Some(fid) = self.fds.iter().position(|fd| fd.is_none()) {
            self.fds[fid] = Some(Default::default());
            Some((fid as u64, self.fds[fid as usize].as_mut().unwrap()))
        } else {
            None
        }
    }

    fn deallocate_fd(&mut self, fd: usize) -> Result<usize, KError> {
        match self.fds.get_mut(fd) {
            Some(fdinfo) => match fdinfo {
                Some(info) => {
                    log::debug!("deallocating: {:?}", info);
                    *fdinfo = None;
                    Ok(fd)
                }
                None => Err(KError::InvalidFileDescriptor),
            },
            None => Err(KError::InvalidFileDescriptor),
        }
    }

    fn get_fd(&self, index: usize) -> &FileDescriptorEntry {
        self.fds[index].as_ref().unwrap()
    }

    fn pinfo(&self) -> &kpi::process::ProcessInfo {
        &self.pinfo
    }

    fn add_frame(&mut self, frame: Frame) -> Result<FrameId, KError> {
        if let Some(fid) = self.frames.iter().position(|fid| fid.is_none()) {
            self.frames[fid] = Some(frame);
            Ok(fid)
        } else {
            Err(KError::TooManyRegisteredFrames)
        }
    }

    fn get_frame(&mut self, frame_id: FrameId) -> Result<Frame, KError> {
        self.frames
            .get(frame_id)
            .cloned()
            .flatten()
            .ok_or(KError::InvalidFrameId)
    }

    fn deallocate_frame(&mut self, fid: FrameId) -> Result<Frame, KError> {
        match self.frames.get_mut(fid) {
            Some(maybe_frame) => {
                let mut old = None;
                core::mem::swap(&mut old, maybe_frame);
                old.ok_or(KError::InvalidFileDescriptor)
            }
            _ => Err(KError::InvalidFileDescriptor),
        }
    }
}

impl Executor for EL0Executor {
    type Resumer = EL0Resumer;

    fn id(&self) -> Eid {
        self.eid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn vcpu_kernel(&self) -> *mut kpi::arch::VirtualCpu {
        self.vcpu_ctl_kernel.as_mut_ptr()
    }

    /// Start the process (run it for the first time).
    fn start(&self) -> Self::Resumer {
        assert_eq!(
            *crate::environment::NODE_ID,
            self.affinity,
            "Run on remote replica?"
        );

        self.maybe_switch_vspace();
        let entry_point = unsafe { (*self.vcpu_kernel()).resume_with_upcall };

        if entry_point == INVALID_EXECUTOR_START {
            EL0Resumer::new_start(self.entry_point, self.stack_top())
        } else {
            // This is similar to `upcall` as it starts executing the defined upcall
            // handler, but on the regular stack (for that dispatcher) and not
            // the upcall stack. It's used to add a new core to a process.

            let entry_point = unsafe { (*self.vcpu_kernel()).resume_with_upcall };
            log::trace!("Added core entry point is at {:#x}", entry_point);
            let cpu_ctl = self.vcpu_addr().as_u64();

            EL0Resumer::new_upcall(
                entry_point,
                self.stack_top(),
                cpu_ctl,
                kpi::upcall::NEW_CORE,
                *crate::environment::CORE_ID as u64,
            )
        }
    }

    fn resume(&self) -> Self::Resumer {
        assert_eq!(
            *crate::environment::NODE_ID,
            self.affinity,
            "Run on remote replica?"
        );

        self.maybe_switch_vspace();
        EL0Resumer::new_restore(&self.save_area as *const kpi::arch::SaveArea)
    }

    fn upcall(&self, vector: u64, exception: u64) -> Self::Resumer {
        assert_eq!(
            *crate::environment::NODE_ID,
            self.affinity,
            "Run on remote replica?"
        );

        self.maybe_switch_vspace();
        let entry_point = self.vcpu().resume_with_upcall;
        let cpu_ctl = self.vcpu_addr().as_u64();

        EL0Resumer::new_upcall(
            entry_point,
            self.upcall_stack_top(),
            cpu_ctl,
            vector,
            exception,
        )
    }

    fn maybe_switch_vspace(&self) {
        unsafe {
            let current_vroot = PAddr::from(TTBR0_EL1.get());
            if current_vroot != self.vroot {
                log::info!("Switching to 0x{:x}", self.vroot);
                TTBR0_EL1.set(self.vroot.into());
            }
        }
    }
}
