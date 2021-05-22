// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Generic process traits
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt::Debug;

use cstr_core::CStr;
use custom_error_core::custom_error;
use kpi::process::{FrameId, ELF_OFFSET};

use crate::arch::memory::{paddr_to_kernel_vaddr, LARGE_PAGE_SIZE};
use crate::arch::process::UserPtr;
use crate::arch::Module;
use crate::error::KError;
use crate::memory::vspace::AddressSpace;
use crate::memory::{Frame, KernelAllocator, PhysicalPageProvider, VAddr};
use crate::mlnrfs::Fd;
use crate::prelude::overlaps;
use crate::{kcb, mlnr, nr, nrproc, round_up};

/// How many (concurrent) processes the systems supports.
pub const MAX_PROCESSES: usize = 12;

/// This struct is used to copy the user buffer into kernel space, so that the
/// user-application doesn't have any reference to any log operation in kernel space.
#[derive(PartialEq, Clone, Debug)]
pub struct KernSlice {
    pub buffer: Arc<[u8]>,
}

impl KernSlice {
    pub fn new(base: u64, len: usize) -> KernSlice {
        let buffer = Arc::<[u8]>::new_uninit_slice(len);
        let mut buffer = unsafe { buffer.assume_init() };

        let mut user_ptr = VAddr::from(base);
        let slice_ptr = UserPtr::new(&mut user_ptr);
        let user_slice: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(slice_ptr.as_mut_ptr(), len) };
        unsafe { Arc::get_mut_unchecked(&mut buffer).copy_from_slice(&user_slice[0..len]) };
        KernSlice { buffer }
    }
}

pub fn userptr_to_str(useraddr: u64) -> Result<String, KError> {
    let mut user_ptr = VAddr::from(useraddr);
    let str_ptr = UserPtr::new(&mut user_ptr);
    unsafe {
        match CStr::from_ptr(str_ptr.as_ptr()).to_str() {
            Ok(path) => {
                if !path.is_ascii() || path.is_empty() {
                    return Err(KError::NotSupported);
                }
                return Ok(String::from(path));
            }
            Err(_) => return Err(KError::NotSupported),
        }
    }
}

/// Process ID.
pub type Pid = usize;

/// Executor ID.
pub type Eid = usize;

custom_error! {
#[derive(PartialEq, Clone)]
pub ProcessError
    ProcessCreate{desc: String}  = "Unable to create process: {desc}",
    ProcessNotSet = "The core has no current process set.",
    NoProcessFoundForPid = "No process was associated with the given Pid.",
    UnableToLoad = "Couldn't load process, invalid ELF file?",
    UnableToParseElf = "Couldn't parse ELF file, invalid?",
    NoExecutorAllocated = "We never allocated executors for this affinity region and process (need to fill cache).",
    ExecutorCacheExhausted = "The executor cache for given affinity is empty (need to refill)",
    InvalidGlobalThreadId = "Specified an invalid core",
    ExecutorNoLongerValid = "The excutor was removed from the current core.",
    ExecutorAlreadyBorrowed = "The executor on the core was already borrowed (that's a bug).",
    NotEnoughMemory = "Unable to reserve memory for internal process data-structures.",
    InvalidFrameId = "The provided FrameId is not registered with the process",
    TooManyProcesses = "Not enough space in process table (out of PIDs).",
}

impl From<&str> for ProcessError {
    fn from(_err: &str) -> Self {
        ProcessError::UnableToLoad
    }
}

impl From<alloc::collections::TryReserveError> for ProcessError {
    fn from(_err: alloc::collections::TryReserveError) -> Self {
        ProcessError::NotEnoughMemory
    }
}

/// Abstract definition of a process.
pub trait Process {
    type E: Executor + Copy + Sync + Send + Debug + PartialEq;
    type A: AddressSpace;

    fn load(
        &mut self,
        pid: Pid,
        module: &Module,
        writable_sections: Vec<Frame>,
    ) -> Result<(), ProcessError>
    where
        Self: core::marker::Sized;

    fn try_reserve_executors(
        &self,
        how_many: usize,
        affinity: atopology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError>;
    fn allocate_executors(&mut self, frame: Frame) -> Result<usize, ProcessError>;

    fn vspace_mut(&mut self) -> &mut Self::A;

    fn vspace(&self) -> &Self::A;

    fn get_executor(&mut self, for_region: atopology::NodeId)
        -> Result<Box<Self::E>, ProcessError>;

    fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)>;

    fn deallocate_fd(&mut self, fd: usize) -> usize;

    fn get_fd(&self, index: usize) -> &Fd;

    fn pinfo(&self) -> &kpi::process::ProcessInfo;

    fn add_frame(&mut self, frame: Frame) -> Result<FrameId, ProcessError>;
    fn get_frame(&mut self, frame_id: FrameId) -> Result<Frame, ProcessError>;
}

/// ResumeHandle is the HW specific logic that switches the CPU
/// to the a new entry point by initializing the registers etc.
pub trait ResumeHandle {
    unsafe fn resume(self) -> !;
}

/// Abstract executor definition.
///
/// An executor is a execution unit of a process.
/// There exists an 1:M relationship (a process can have many executors).
///
/// # Naming
/// Some operating-systems (K42, Nemesis, Barrelfish etc.) would call this
/// a dispatcher, we avoid the term because it overlaps with the node-replication
/// dispatch trait.
pub trait Executor {
    type Resumer: ResumeHandle;
    fn id(&self) -> Eid;
    fn pid(&self) -> Pid;
    fn start(&self) -> Self::Resumer;
    fn resume(&self) -> Self::Resumer;
    fn upcall(&self, vector: u64, exception: u64) -> Self::Resumer;
    fn maybe_switch_vspace(&self);
    fn vcpu_kernel(&self) -> *mut kpi::arch::VirtualCpu;
}

/// An elfloader implementation that only loads the writeable sections of the program.
struct DataSecAllocator {
    offset: VAddr,
    frames: Vec<(usize, Frame)>,
}

impl DataSecAllocator {
    /// We can call finish on it to return the ordered list of frames that were
    /// used for the writeable section.
    fn finish(self) -> Vec<Frame> {
        self.frames
            .into_iter()
            .map(|(_offset, base)| base)
            .collect()
    }
}

impl elfloader::ElfLoader for DataSecAllocator {
    fn allocate(&mut self, load_headers: elfloader::LoadableHeaders) -> Result<(), &'static str> {
        for header in load_headers.into_iter() {
            let base = header.virtual_addr();
            let size = header.mem_size() as usize;
            let flags = header.flags();

            // Calculate the offset and align to page boundaries
            // We can't expect to get something that is page-aligned from ELF
            let page_mask = (LARGE_PAGE_SIZE - 1) as u64;
            let page_base: VAddr = VAddr::from(base & !page_mask); // Round down to nearest page-size
            let size_page = round_up!(size + (base & page_mask) as usize, LARGE_PAGE_SIZE as usize);
            assert!(size_page >= size);
            assert_eq!(size_page % LARGE_PAGE_SIZE, 0);
            assert_eq!(page_base % LARGE_PAGE_SIZE, 0);

            if flags.is_write() {
                trace!(
                    "base = {:#x} size = {:#x} page_base = {:#x} size_page = {:#x}",
                    base,
                    size,
                    page_base,
                    size_page
                );
                let large_pages = size_page / LARGE_PAGE_SIZE;
                KernelAllocator::try_refill_tcache(0, large_pages).expect("Refill didn't work");

                let kcb = crate::kcb::get_kcb();
                let mut pmanager = kcb.mem_manager();
                for i in 0..large_pages {
                    let frame = pmanager
                        .allocate_large_page()
                        .expect("We refilled so allocation should work.");

                    trace!(
                        "add to self.frames  (elf_va={:#x}, pa={:#x})",
                        page_base.as_usize() + i * LARGE_PAGE_SIZE,
                        frame.base
                    );

                    self.frames
                        .push((page_base.as_usize() + i * LARGE_PAGE_SIZE, frame));
                }
            }
        }
        Ok(())
    }

    fn load(
        &mut self,
        flags: elfloader::Flags,
        destination: u64,
        region: &[u8],
    ) -> Result<(), &'static str> {
        debug!(
            "load(): destination = {:#x} region.len() = {:#x}",
            destination,
            region.len(),
        );

        if flags.is_write() {
            let mut destination: usize = destination.try_into().unwrap();
            let mut region_remaining = region.len();
            let mut region = region;

            // Iterate over all frames to check which region(s) overlaps with it (so we'd need to copy)
            for (elf_begin, frame) in self.frames.iter() {
                trace!(
                    "load(): into process vspace at {:#x} #bytes {:#x} offset_in_frame = {:#x}",
                    destination,
                    region.len(),
                    *elf_begin
                );

                // Compute range interval (in ELF space) for both the current frame
                // and the region we want to copy into frames
                let range_frame_elf = *elf_begin..*elf_begin + frame.size;
                let range_region_elf = destination..destination + region_remaining;

                if overlaps(&range_region_elf, &range_frame_elf) {
                    trace!(
                            "The frame overlaps with copy region (range_frame_elf={:x?} range_region_elf={:x?})",
                            range_frame_elf, range_region_elf
                        );

                    // Figure out which sub-slice of region goes into the frame
                    // i.e., compute the intersection of two ranges
                    let copy_start =
                        core::cmp::max(range_frame_elf.start, range_region_elf.start) - destination;
                    let copy_end =
                        core::cmp::min(range_frame_elf.end, range_region_elf.end) - destination;
                    let region_to_copy = &region[copy_start..copy_end];
                    trace!("copy range = {:x?}", copy_start..copy_end);

                    // Figure out where `destination` is relative to the frame base
                    let copy_in_frame_start = destination - *elf_begin;
                    let frame_vaddr = paddr_to_kernel_vaddr(frame.base);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            region_to_copy.as_ptr(),
                            frame_vaddr.as_mut_ptr::<u8>().add(copy_in_frame_start),
                            copy_end - copy_start,
                        );
                        trace!(
                            "Copied {} bytes from {:p} to {:p}",
                            copy_end - copy_start,
                            region_to_copy.as_ptr(),
                            frame_vaddr.as_mut_ptr::<u8>().add(copy_start)
                        );

                        destination += copy_end - copy_start;
                        region = &region[copy_end..];
                        region_remaining -= copy_end - copy_start;
                    }
                }
            }
        }

        Ok(())
    }

    fn relocate(&mut self, entry: &elfloader::Rela<elfloader::P64>) -> Result<(), &'static str> {
        // Get the pointer to where the relocation happens in the
        // memory where we loaded the headers
        // The forumla for this is our offset where the kernel is starting,
        // plus the offset of the entry to jump to the code piece
        let addr = self.offset + entry.get_offset();

        // Only relocate stuff in write-only frames that don't get replicated:
        for (pheader_offset, frame) in self.frames.iter() {
            let elf_vbase = (self.offset + *pheader_offset) & !(LARGE_PAGE_SIZE - 1);
            if addr >= elf_vbase && addr <= elf_vbase + frame.size() {
                // Relocation is within this frame
                let kernel_vaddr = paddr_to_kernel_vaddr(frame.base);
                let offset_in_frame = addr - elf_vbase;

                let kernel_addr = kernel_vaddr + offset_in_frame;
                trace!(
                    "DataSecAllocator relocation paddr {:#x} kernel_addr {:#x}",
                    offset_in_frame + frame.base.as_u64(),
                    kernel_addr
                );
                use elfloader::TypeRela64;
                if let TypeRela64::R_RELATIVE = TypeRela64::from(entry.get_type()) {
                    // This is a relative relocation of a 64 bit value, we add the offset (where we put our
                    // binary in the vspace) to the addend and we're done:
                    unsafe {
                        // Scary unsafe changing stuff in random memory locations based on
                        // ELF binary values weee!
                        *(kernel_addr.as_mut_ptr::<u64>()) =
                            self.offset.as_u64() + entry.get_addend();
                    }
                } else {
                    return Err("Can only handle R_RELATIVE for relocation");
                }
            }
        }

        Ok(())
    }
}

/// Create a new process
///
/// Parse & relocate ELF
/// Create an initial VSpace
pub fn make_process<P>(binary: &'static str) -> Result<Pid, KError>
where
    P: crate::process::Process<E = crate::arch::process::ArchExecutor>,
{
    KernelAllocator::try_refill_tcache(7, 1)?;
    let kcb = kcb::get_kcb();

    // Lookup binary of the process
    let mut mod_file = None;
    for module in &kcb.arch.kernel_args().modules {
        if module.name() == binary {
            mod_file = Some(module);
        }
    }

    let mod_file = mod_file.expect(format!("Couldn't find '{}' binary.", binary).as_str());
    info!(
        "binary={} cmdline={} module={:?}",
        binary, kcb.cmdline.test_cmdline, mod_file
    );

    let elf_module = unsafe {
        elfloader::ElfBinary::new(mod_file.name(), mod_file.as_slice())
            .map_err(|_e| ProcessError::UnableToParseElf)?
    };

    // We don't have an offset for non-pie applications (i.e., rump apps)
    let offset = if !elf_module.is_pie() {
        VAddr::zero()
    } else {
        VAddr::from(ELF_OFFSET)
    };

    let mut data_sec_loader = DataSecAllocator {
        offset,
        frames: Vec::with_capacity(2),
    };
    elf_module
        .load(&mut data_sec_loader)
        .map_err(|_e| ProcessError::UnableToLoad)?;
    let data_frames: Vec<Frame> = data_sec_loader.finish();

    // Allocate a new process
    kcb.replica
        .as_ref()
        .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
            let response = replica.execute_mut(nr::Op::AllocatePid, *token)?;
            if let nr::NodeResult::PidAllocated(pid) = response {
                mlnr::MlnrKernelNode::add_process(pid)?;
                crate::nrproc::NrProcess::<P>::load(pid, mod_file, data_frames)?;
                Ok(pid)
            } else {
                Err(KError::ProcessLoadingFailed)
            }
        })
}

/*pub fn make_process2(binary: &'static str) -> Result<Replica<Process>, KError> {
    KernelAllocator::try_refill_tcache(7, 1)?;
    let kcb = kcb::get_kcb();

    // Lookup binary of the process
    let mut mod_file = None;
    for module in &kcb.arch.kernel_args().modules {
        if module.name() == binary {
            mod_file = Some(module);
        }
    }

    let mod_file = mod_file.expect(format!("Couldn't find '{}' binary.", binary).as_str());
    info!(
        "binary={} cmdline={} module={:?}",
        binary, kcb.cmdline.test_cmdline, mod_file
    );

    let elf_module = unsafe {
        elfloader::ElfBinary::new(mod_file.name(), mod_file.as_slice())
            .map_err(|_e| ProcessError::UnableToParseElf)?
    };

    // We don't have an offset for non-pie applications (i.e., rump apps)
    let offset = if !elf_module.is_pie() {
        VAddr::zero()
    } else {
        VAddr::from(0x20_0000_0000usize)
    };

    let mut data_sec_loader = DataSecAllocator {
        offset,
        frames: Vec::with_capacity(2),
    };
    elf_module
        .load(&mut data_sec_loader)
        .map_err(|_e| ProcessError::UnableToLoad)?;
    let data_frames: Vec<Frame> = data_sec_loader.finish();

    // Create a new process
    kcb.replica
        .as_ref()
        .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
            let response = replica.execute_mut(nr::Op::ProcCreate(&mod_file, data_frames), *token);
            match response {
                Ok(nr::NodeResult::ProcCreated(pid)) => {
                    match mlnr::MlnrKernelNode::add_process(pid) {
                        Ok(pid) => Ok(pid.0),
                        Err(e) => unreachable!("{}", e),
                    }
                }
                _ => unreachable!("Got unexpected response"),
            }
        })
}*/

/// Create dispatchers for a given Pid to run on all cores.
///
/// Also make sure they are all using NUMA local memory
pub fn allocate_dispatchers<P: Process>(pid: Pid) -> Result<(), KError>
where
    P: crate::process::Process<E = crate::arch::process::ArchExecutor>,
{
    trace!("Allocate dispatchers");

    let mut create_per_region: Vec<(atopology::NodeId, usize)> =
        Vec::with_capacity(atopology::MACHINE_TOPOLOGY.num_nodes() + 1);

    if atopology::MACHINE_TOPOLOGY.num_nodes() > 0 {
        for node in atopology::MACHINE_TOPOLOGY.nodes() {
            let threads = node.threads().count();
            create_per_region.push((node.id, threads));
        }
    } else {
        create_per_region.push((0, atopology::MACHINE_TOPOLOGY.num_threads()));
    }

    for (affinity, to_create) in create_per_region {
        let mut dispatchers_created = 0;
        while dispatchers_created < to_create {
            KernelAllocator::try_refill_tcache(20, 1)?;
            let mut frame = {
                let kcb = crate::kcb::get_kcb();
                kcb.physical_memory.gmanager.unwrap().node_caches[affinity as usize]
                    .lock()
                    .allocate_large_page()?
            };

            unsafe {
                frame.zero();
            }

            match nrproc::NrProcess::<P>::allocate_dispatchers(pid, frame) {
                Ok(count) => {
                    dispatchers_created += count;
                }
                _ => unreachable!("Got unexpected response"),
            }
        }
    }

    debug!("Allocated dispatchers");
    Ok(())
}
