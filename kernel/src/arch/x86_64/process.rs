// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::collections::TryReserveError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::PartialEq;
use core::ops::{Deref, DerefMut};
use core::{fmt, ptr};

use arrayvec::ArrayVec;
use fallible_collections::try_vec;
use fallible_collections::FallibleVec;
use kpi::process::{FrameId, ELF_OFFSET, EXECUTOR_OFFSET};
use lazy_static::lazy_static;
use log::{debug, info, trace, warn};
use node_replication::{Dispatch, Log, Replica};
use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

use crate::error::KError;
use crate::fs::{Fd, MAX_FILES_PER_PROCESS};
use crate::kcb::ArchSpecificKcb;
use crate::kcb::{self, Kcb};
use crate::memory::detmem::DA;
use crate::memory::vspace::{AddressSpace, MapAction};
use crate::memory::{paddr_to_kernel_vaddr, Frame, KernelAllocator, PAddr, VAddr};
use crate::nrproc::NrProcess;
use crate::process::{
    Eid, Executor, Pid, Process, ResumeHandle, MAX_FRAMES_PER_PROCESS, MAX_PROCESSES,
    MAX_WRITEABLE_SECTIONS_PER_PROCESS,
};
use crate::round_up;

use super::kcb::Arch86Kcb;
use super::vspace::*;
use super::Module;
use super::MAX_NUMA_NODES;

const INVALID_EXECUTOR_START: VAddr = VAddr(0xdeadffff);

lazy_static! {
    pub static ref PROCESS_TABLE: ArrayVec<ArrayVec<Arc<Replica<'static, NrProcess<Ring3Process>>>, MAX_PROCESSES>, MAX_NUMA_NODES> = {
        // Want at least one replica...
        let numa_nodes = core::cmp::max(1, atopology::MACHINE_TOPOLOGY.num_nodes());

        let mut numa_cache = ArrayVec::new();
        for _n in 0..numa_nodes {
            let process_replicas = ArrayVec::new();
            debug_assert!(!numa_cache.is_full());
            numa_cache.push(process_replicas)
        }

        for pid in 0..MAX_PROCESSES {
                let log = Arc::try_new(Log::<<NrProcess<Ring3Process> as Dispatch>::WriteOperation>::new(
                    LARGE_PAGE_SIZE,
                )).expect("Can't initialize processes, out of memory.");

            let da = DA::new().expect("Can't initialize process deterministic memory allocator");
            for node in 0..numa_nodes {
                let kcb = kcb::get_kcb();
                kcb.set_allocation_affinity(node as atopology::NodeId).expect("Can't change affinity");
                debug_assert!(!numa_cache[node].is_full());

                let p = Box::try_new(Ring3Process::new(pid, da.clone()).expect("Can't create process during init")).expect("Not enough memory to initialize processes");
                let nrp = NrProcess::new(p, da.clone());

                numa_cache[node].push(Replica::<NrProcess<Ring3Process>>::with_data(&log, nrp));

                debug_assert_eq!(kcb.arch.node(), 0, "Expect initialization to happen on node 0.");
                kcb.set_allocation_affinity(0 as atopology::NodeId).expect("Can't change affinity");
            }
        }

        numa_cache
    };
}

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

pub struct UserSlice<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> UserSlice<'a> {
    pub fn new(base: u64, len: usize) -> UserSlice<'a> {
        let mut user_ptr = VAddr::from(base);
        let slice_ptr = UserPtr::new(&mut user_ptr);
        let user_slice: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(slice_ptr.as_mut_ptr(), len) };
        UserSlice { buffer: user_slice }
    }
}

impl<'a> Deref for UserSlice<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe {
            rflags::stac();
            &*self.buffer
        }
    }
}

impl<'a> DerefMut for UserSlice<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            rflags::stac();
            self.buffer
        }
    }
}

impl<'a> Drop for UserSlice<'a> {
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
    typ: ResumeStrategy,
    pub save_area: *const kpi::arch::SaveArea,

    entry_point: VAddr,
    stack_top: VAddr,
    cpu_ctl: u64,
    vector: u64,
    exception: u64,
}

impl ResumeHandle for Ring3Resumer {
    unsafe fn resume(self) -> ! {
        match self.typ {
            ResumeStrategy::Start => self.start(),
            ResumeStrategy::Upcall => self.upcall(),
            ResumeStrategy::SysRet => self.restore(),
            ResumeStrategy::IRet => self.iret_restore(),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
enum ResumeStrategy {
    Start,
    SysRet,
    IRet,
    Upcall,
}

impl Ring3Resumer {
    pub fn new_iret(save_area: *const kpi::arch::SaveArea) -> Ring3Resumer {
        Ring3Resumer {
            typ: ResumeStrategy::IRet,
            save_area: save_area,
            entry_point: VAddr::zero(),
            stack_top: VAddr::zero(),
            cpu_ctl: 0,
            vector: 0,
            exception: 0,
        }
    }

    pub fn new_restore(save_area: *const kpi::arch::SaveArea) -> Ring3Resumer {
        Ring3Resumer {
            typ: ResumeStrategy::SysRet,
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
            typ: ResumeStrategy::Upcall,
            save_area: ptr::null(),
            entry_point,
            stack_top,
            cpu_ctl,
            vector,
            exception,
        }
    }

    pub fn new_start(entry_point: VAddr, stack_top: VAddr) -> Ring3Resumer {
        Ring3Resumer {
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
        //info!("resuming User-space with ctxt: {:?}", (*(self.save_area)),);

        // Resumes a process using iretq
        llvm_asm!("
                // Restore fs and gs registers
                swapgs
                movq 19*8(%rdi), %rsi
                wrfsbase %rsi

                // Restore vector registers
                fxrstor 24*8(%rdi)

                // Restore CPU registers
                movq  0*8(%rdi), %rax
                movq  1*8(%rdi), %rbx
                movq  2*8(%rdi), %rcx
                movq  3*8(%rdi), %rdx
                movq  4*8(%rdi), %rsi
                // %rdi: Restore last (see below) to preserve `save_area`
                movq  6*8(%rdi), %rbp
                // %rsp: Restored through iretq stack set-up
                movq  8*8(%rdi), %r8
                movq  9*8(%rdi), %r9
                movq 10*8(%rdi), %r10
                movq 11*8(%rdi), %r11
                movq 12*8(%rdi), %r12
                movq 13*8(%rdi), %r13
                movq 14*8(%rdi), %r14
                movq 15*8(%rdi), %r15

                // SS (TODO(style): hard-coded constant)
                pushq $$35
                // %rsp
                pushq 7*8(%rdi)
                // RFLAGS
                pushq 17*8(%rdi)
                // Code-segment (TODO(style): hard-coded constant)
                pushq $$27
                // %rip
                pushq 16*8(%rdi)

                // Restore rdi register last, since it was used to reach `state`
                movq 5*8(%rdi), %rdi
                iretq
                " ::
            "{rdi}" (self.save_area));

        unreachable!("We should not come here!");
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
        llvm_asm!("
                // Restore CPU registers
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
        llvm_asm!("
                // rax: contains stack pointer
                movq       $$0, %rbx
                // rcx: has entry point
                // rdi: 1st argument
                // rsi: 2nd argument
                // rdx: 3rd argument
                // rsp and rbp are set to provided `stack_top`
                movq       $$0, %r8
                movq       $$0, %r9
                movq       $$0, %r10
                // r11 register is used for RFlags
                movq       $$0, %r12
                movq       $$0, %r13
                movq       $$0, %r14
                movq       $$0, %r15

                // Reset vector registers
                fninit

                swapgs
                // TODO: restore fs register

                movq %rax, %rbp
                movq %rax, %rsp

                sysretq
            " ::
            "{rcx}" (self.entry_point.as_u64())
            "{rdi}" (self.cpu_ctl)
            "{rsi}" (self.vector)
            "{rdx}" (self.exception)
            "{rax}" (self.stack_top.as_u64())
            "{r11}" (user_flags.bits())
        );

        unreachable!("We should not come here!");
    }

    unsafe fn start(self) -> ! {
        trace!("About to go to user-space: {:#x}", self.entry_point);
        warn!("Make sure IA32_KERNEL_GSBASE still points to KCB!");
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
        llvm_asm!("
                // rax: contains stack pointer
                movq       $$0, %rbx
                // rcx: has entry point
                // rdi: 1st argument
                // rsi: 2nd argument
                // rdx: 3rd argument
                // rsp and rbp are set to provided `stack_top`
                movq       $$0, %r8
                movq       $$0, %r9
                movq       $$0, %r10
                // r11 register is used for RFlags
                movq       $$0, %r12
                movq       $$0, %r13
                movq       $$0, %r14
                movq       $$0, %r15

                // Reset vector registers
                fninit

                // Set gs and fs to 0
                wrgsbase %r15
                wrfsbase %r15

                movq %rax, %rbp
                movq %rax, %rsp

                sysretq
            " ::
            "{rcx}" (self.entry_point.as_u64())
            "{rdi}" (self.cpu_ctl)
            "{rsi}" (self.vector)
            "{rdx}" (self.exception)
            "{rax}" (self.stack_top.as_u64())
            "{r11}" (user_flags.bits())
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
    pub pml4: PAddr,
}

// CPU context save area (must be first, see exec.S)
static_assertions::const_assert_eq!(memoffset::offset_of!(Ring3Executor, save_area), 0);

impl PartialEq<Ring3Executor> for Ring3Executor {
    fn eq(&self, other: &Ring3Executor) -> bool {
        self.pid == other.pid && self.eid == other.eid
    }
}

impl Ring3Executor {
    /// Size of the init stack (i.e., initial stack when the dispatcher starts running).
    const INIT_STACK_SIZE: usize = 24 * BASE_PAGE_SIZE;
    /// Size of the upcall signal stack for the dispatcher.
    const UPCALL_STACK_SIZE: usize = 24 * BASE_PAGE_SIZE;
    /// Total memory consumption (in a process' vspace) that the executor uses.
    /// (2 stacks plus the VirtualCpu struct.)
    const EXECUTOR_SPACE_REQUIREMENT: usize =
        Ring3Executor::INIT_STACK_SIZE + Ring3Executor::UPCALL_STACK_SIZE + BASE_PAGE_SIZE;

    fn new(
        process: &Ring3Process,
        eid: Eid,
        vcpu_ctl_kernel: VAddr,
        region: (VAddr, VAddr),
        affinity: atopology::NodeId,
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
            vcpu_ctl_kernel,
            vcpu_ctl: vcpu_vaddr,
            save_area: Default::default(),
            entry_point: process.offset + process.entry_point,
            // Note: The PML4 is a bit awkward here, we must ensure to use the
            // PML4 of the local replica, but aside from some asserts in
            // `start`, `resume` etc. nothing prevents us from running this
            // executor on a different replica (which means the advance log on
            // pfault would not really advance the right set of page-tables)
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

impl fmt::Display for Ring3Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ring3Executor {}", self.eid)
    }
}

impl Executor for Ring3Executor {
    type Resumer = Ring3Resumer;

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
        let kcb = kcb::get_kcb();
        assert_eq!(kcb.arch.node(), self.affinity, "Run on remote replica?");

        self.maybe_switch_vspace();
        let entry_point = unsafe { (*self.vcpu_kernel()).resume_with_upcall };

        if entry_point == INVALID_EXECUTOR_START {
            Ring3Resumer::new_start(self.entry_point, self.stack_top())
        } else {
            // This is similar to `upcall` as it starts executing the defined upcall
            // handler, but on the regular stack (for that dispatcher) and not
            // the upcall stack. It's used to add a new core to a process.

            let entry_point = unsafe { (*self.vcpu_kernel()).resume_with_upcall };
            trace!("Added core entry point is at {:#x}", entry_point);
            let cpu_ctl = self.vcpu().vaddr().as_u64();

            Ring3Resumer::new_upcall(
                entry_point,
                self.stack_top(),
                cpu_ctl,
                kpi::upcall::NEW_CORE,
                kcb.arch.id() as u64,
            )
        }
    }

    fn resume(&self) -> Self::Resumer {
        assert_eq!(kcb::get_kcb().node, self.affinity, "Run on remote replica?");

        self.maybe_switch_vspace();
        Ring3Resumer::new_restore(&self.save_area as *const kpi::arch::SaveArea)
    }

    fn upcall(&self, vector: u64, exception: u64) -> Self::Resumer {
        assert_eq!(kcb::get_kcb().node, self.affinity, "Run on remote replica?");

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
    /// Process info struct (can be retrieved by user-space)
    pub pinfo: kpi::process::ProcessInfo,
    /// The entry point of the ELF file (set during elfloading).
    pub entry_point: VAddr,
    /// Executor cache (holds a per-region cache of executors)
    pub executor_cache: ArrayVec<Option<Vec<Box<Ring3Executor>>>, MAX_NUMA_NODES>,
    /// Offset where executor memory is located in user-space.
    pub executor_offset: VAddr,
    /// File descriptors for the opened file.
    pub fds: ArrayVec<Option<Fd>, MAX_FILES_PER_PROCESS>,
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

impl Ring3Process {
    fn new(pid: Pid, da: DA) -> Result<Self, KError> {
        const NONE_EXECUTOR: Option<Vec<Box<Ring3Executor>>> = None;
        let executor_cache: ArrayVec<Option<Vec<Box<Ring3Executor>>>, MAX_NUMA_NODES> =
            ArrayVec::from([NONE_EXECUTOR; MAX_NUMA_NODES]);

        const NONE_FD: Option<Fd> = None;
        let fds: ArrayVec<Option<Fd>, MAX_FILES_PER_PROCESS> =
            ArrayVec::from([NONE_FD; MAX_FILES_PER_PROCESS]);

        let frames: ArrayVec<Option<Frame>, MAX_FRAMES_PER_PROCESS> =
            ArrayVec::from([None; MAX_FRAMES_PER_PROCESS]);

        Ok(Ring3Process {
            pid: pid,
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
                (true, true, true) => MapAction::ReadWriteExecuteUser,
            };

            info!(
                "ELF Allocate: {:#x} -- {:#x} align to {:#x} with flags {:?} ({:?})",
                page_base,
                page_base + size_page,
                align_to,
                flags,
                map_action
            );

            let large_pages = size_page / LARGE_PAGE_SIZE;
            debug!("page_base {} lps: {}", page_base, large_pages);

            // TODO(correctness): add 20 as estimate of worst case pt requirements
            KernelAllocator::try_refill_tcache(20, large_pages).expect("Refill didn't work");

            let kcb = crate::kcb::get_kcb();

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
                    let mut pmanager = kcb.mem_manager();
                    pmanager
                        .allocate_large_page()
                        .expect("We refilled so allocation should work.")
                };

                trace!(
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

        info!(
            "Binary loaded at address: {:#x} entry {:#x}",
            self.offset, self.entry_point
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
            info!(
                "ELF Load of read-only region at {:#x} -- {:#x}",
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

                // TODO(perf): Inefficient byte-wise copy also within a 4 KiB /
                // 2 MiB page we don't have to resolve_addr every time
                if idx == 0 {
                    trace!(
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
            debug!(
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
        entry: &elfloader::Rela<elfloader::P64>,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        // Get the pointer to where the relocation happens in the
        // memory where we loaded the headers
        // The forumla for this is our offset where the kernel is starting,
        // plus the offset of the entry to jump to the code piece
        let addr = self.offset + entry.get_offset();

        if addr >= self.read_only_offset {
            // Don't relocate anything in write-able section, already done
            return Ok(());
        }

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
            Err(elfloader::ElfLoaderErr::UnsupportedRelocationEntry)
        }
    }

    fn make_readonly(&mut self, base: u64, size: usize) -> Result<(), elfloader::ElfLoaderErr> {
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

impl Process for Ring3Process {
    type E = Ring3Executor;
    type A = VSpace;

    /// Create a process from a module
    fn load(
        &mut self,
        pid: Pid,
        module: &Module,
        writeable_sections: Vec<Frame>,
    ) -> Result<(), KError> {
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

        // Install the kernel mappings
        // TODO(efficiency): These should probably be global mappings
        // TODO(broken): Big (>= 2 MiB) allocations should be inserted here too
        // TODO(ugly): Find a better way to express this mess
        super::kcb::try_get_kcb().map(|kcb: &mut Kcb<Arch86Kcb>| {
            for i in 128..=135 {
                let kernel_pml_entry = kcb.arch.init_vspace().pml4[i];
                trace!("Patched in kernel mappings at {:?}", kernel_pml_entry);
                self.vspace.page_table.pml4[i] = kernel_pml_entry;
            }
        });

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

    fn vspace_mut(&mut self) -> &mut VSpace {
        &mut self.vspace
    }

    fn vspace(&self) -> &VSpace {
        &self.vspace
    }

    fn get_executor(
        &mut self,
        for_region: atopology::NodeId,
    ) -> Result<Box<Ring3Executor>, KError> {
        match &mut self.executor_cache[for_region as usize] {
            Some(ref mut executor_list) => {
                let ret = executor_list.pop().ok_or(KError::ExecutorCacheExhausted)?;
                //info!("get executor {} with affinity {}", ret.eid, for_region);
                Ok(ret)
            }
            None => Err(KError::NoExecutorAllocated),
        }
    }

    /// Create a series of dispatcher objects for the process
    fn allocate_executors(&mut self, memory: Frame) -> Result<usize, KError> {
        let executor_space_requirement = Ring3Executor::EXECUTOR_SPACE_REQUIREMENT;
        let executors_to_create = memory.size() / executor_space_requirement;

        KernelAllocator::try_refill_tcache(20, 0).expect("Refill didn't work");
        {
            self.vspace
                .map_frame(self.executor_offset, memory, MapAction::ReadWriteUser)
                .expect("Can't map user-space executor memory.");

            info!(
                "executor space base expanded {:#x} size: {} end {:#x}",
                self.executor_offset,
                memory.size(),
                self.executor_offset + memory.size()
            );
        }

        let cur_paddr_offset = memory.base;
        let mut cur_offset = self.executor_offset;
        for _cnt in 0..executors_to_create {
            let executor_vmem_start = cur_offset;
            let executor_pmem_start = cur_paddr_offset;

            let executor_vmem_end = executor_vmem_start + executor_space_requirement;
            let _executor_pmem_end = executor_pmem_start + executor_space_requirement;

            let _upcall_stack_base = cur_offset + Ring3Executor::INIT_STACK_SIZE;
            let _vcpu_ctl =
                cur_offset + Ring3Executor::INIT_STACK_SIZE + Ring3Executor::UPCALL_STACK_SIZE;
            let vcpu_ctl_paddr = cur_paddr_offset
                + Ring3Executor::INIT_STACK_SIZE
                + Ring3Executor::UPCALL_STACK_SIZE;

            let executor = Box::try_new(Ring3Executor::new(
                &self,
                self.current_eid,
                crate::memory::paddr_to_kernel_vaddr(PAddr::from(vcpu_ctl_paddr)),
                (executor_vmem_start, executor_vmem_end),
                memory.affinity,
            ))?;

            debug!("Created {} affinity {}", executor, memory.affinity);

            // TODO(error-handling): Check that this properly unwinds on alloc errors...
            match &mut self.executor_cache[memory.affinity as usize] {
                Some(ref mut vector) => vector.try_push(executor)?,
                None => self.executor_cache[memory.affinity as usize] = Some(try_vec![executor]?),
            }

            self.current_eid += 1;
            cur_offset += executor_space_requirement;
        }

        debug!(
            "Created allocators in {:#x} -- {:#x} (we now have {} in total)",
            self.executor_offset,
            self.executor_offset + memory.size(),
            self.current_eid
        );

        self.executor_offset += memory.size();
        Ok(executors_to_create)
    }

    fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)> {
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

    fn get_fd(&self, index: usize) -> &Fd {
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
pub fn spawn(binary: &'static str) -> Result<Pid, KError> {
    use crate::nr;
    use crate::process::{allocate_dispatchers, make_process};

    let pid = make_process::<Ring3Process>(binary)?;
    allocate_dispatchers::<Ring3Process>(pid)?;

    // Set current thread to run executor from our process (on the current core)
    let kcb = kcb::get_kcb();

    let _gtid = nr::KernelNode::allocate_core_to_process(
        pid,
        INVALID_EXECUTOR_START, // This VAddr is irrelevant as it is overriden later
        Some(kcb.arch.node_id),
        Some(kcb.arch.id),
    )?;

    Ok(pid)
}
