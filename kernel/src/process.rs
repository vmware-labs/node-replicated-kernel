// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Generic process traits
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::fmt::Debug;
use core::mem::MaybeUninit;

use arrayvec::ArrayVec;
use fallible_collections::vec::FallibleVecGlobal;
use fallible_collections::vec::TryCollect;
use fallible_collections::TryReserveError;
use kpi::process::{FrameId, ELF_OFFSET};
use kpi::MemType;
use log::{debug, info, trace};

use crate::arch::kcb::per_core_mem;
use crate::arch::memory::{paddr_to_kernel_vaddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use crate::arch::process::{current_pid, with_user_space_access_enabled, ArchProcess};
use crate::arch::{Module, MAX_CORES, MAX_NUMA_NODES};
use crate::cmdline::CommandLineArguments;
use crate::error::{KError, KResult};
use crate::fs::{cnrfs, fd::FileDescriptorEntry};
use crate::memory::backends::PhysicalPageProvider;
use crate::memory::vspace::AddressSpace;
use crate::memory::{Frame, KernelAllocator, PAddr, VAddr, KERNEL_BASE};
use crate::prelude::overlaps;
use crate::{nr, nrproc, round_up};

/// Process ID.
pub(crate) type Pid = usize;

/// Executor ID.
pub(crate) type Eid = usize;

/// How many (concurrent) processes the systems supports.
pub(crate) const MAX_PROCESSES: usize = 12;

/// How many registered "named" frames a process can have.
pub(crate) const MAX_FRAMES_PER_PROCESS: usize = MAX_CORES;

/// How many writable sections a process can have (part of the ELF file).
pub(crate) const MAX_WRITEABLE_SECTIONS_PER_PROCESS: usize = 4;

/// Abstract definition of a process.
pub(crate) trait Process: FrameManagement {
    type E: Executor + Copy + Sync + Send + Debug + PartialEq;
    type A: AddressSpace;

    fn pid(&self) -> Pid;

    fn load(
        &mut self,
        pid: Pid,
        module: &Module,
        writable_sections: Vec<Frame>,
    ) -> Result<(), KError>
    where
        Self: core::marker::Sized;

    fn try_reserve_executors(
        &self,
        how_many: usize,
        affinity: atopology::NodeId,
    ) -> Result<(), alloc::collections::TryReserveError>;
    fn allocate_executors(&mut self, frame: Frame) -> Result<usize, KError>;

    fn vspace_mut(&mut self) -> &mut Self::A;

    fn vspace(&self) -> &Self::A;

    fn get_executor(&mut self, for_region: atopology::NodeId) -> Result<Box<Self::E>, KError>;

    fn allocate_fd(&mut self) -> Option<(u64, &mut FileDescriptorEntry)>;

    fn deallocate_fd(&mut self, fd: usize) -> Result<usize, KError>;

    fn get_fd(&self, index: usize) -> &FileDescriptorEntry;

    fn pinfo(&self) -> &kpi::process::ProcessInfo;
}

pub(crate) trait FrameManagement {
    fn add_frame(&mut self, frame: Frame) -> Result<FrameId, KError>;
    fn get_frame(&mut self, frame_id: FrameId) -> Result<(Frame, usize), KError>;
    fn add_frame_mapping(&mut self, frame_id: FrameId, vaddr: VAddr) -> Result<(), KError>;
    fn remove_frame_mapping(&mut self, paddr: PAddr, _vaddr: VAddr) -> Result<(), KError>;
    fn deallocate_frame(&mut self, fid: FrameId) -> Result<Frame, KError>;
}

/// Implementation for managing a process' frames.
pub(crate) struct ProcessFrames {
    /// Physical frame objects registered to the process.
    frames: ArrayVec<(Option<Frame>, usize), MAX_FRAMES_PER_PROCESS>,
}

impl Default for ProcessFrames {
    fn default() -> Self {
        let frames: ArrayVec<(Option<Frame>, usize), MAX_FRAMES_PER_PROCESS> =
            ArrayVec::from([(None, 0); MAX_FRAMES_PER_PROCESS]);
        Self { frames }
    }
}

impl FrameManagement for ProcessFrames {
    fn add_frame(&mut self, frame: Frame) -> Result<FrameId, KError> {
        if let Some(fid) = self.frames.iter().position(|entry| entry.0.is_none()) {
            self.frames[fid] = (Some(frame), 0);
            Ok(fid)
        } else {
            Err(KError::TooManyRegisteredFrames)
        }
    }

    fn get_frame(&mut self, frame_id: FrameId) -> Result<(Frame, usize), KError> {
        let (frame, metadata) = self
            .frames
            .get(frame_id)
            .cloned()
            .ok_or(KError::InvalidFrameId)?;

        if let Some(frame) = frame {
            Ok((frame, metadata))
        } else {
            Err(KError::InvalidFrameId)
        }
    }

    fn add_frame_mapping(&mut self, frame_id: FrameId, _vaddr: VAddr) -> Result<(), KError> {
        self.frames
            .get_mut(frame_id)
            .and_then(|(frame, ref mut refcnt)| {
                if frame.is_some() {
                    *refcnt += 1;
                    Some(())
                } else {
                    None
                }
            })
            .ok_or(KError::InvalidFrameId)
    }

    fn remove_frame_mapping(&mut self, paddr: PAddr, _vaddr: VAddr) -> Result<(), KError> {
        // If `self.frames` is too big, the O(n) lookup in this fn might become
        // a problem. better to implement some reverse-map for PAddr -> FrameId
        // then.
        static_assertions::const_assert!(MAX_FRAMES_PER_PROCESS < 1024);

        for (frame, ref mut refcnt) in self.frames.iter_mut() {
            if let Some(frame) = frame {
                if frame.base == paddr && *refcnt > 0 {
                    *refcnt -= 1;
                    return Ok(());
                } else {
                    panic!("Can't call remove_frame_mapping on 0 refcnt frame");
                }
            }
        }
        // Frame not found
        Err(KError::InvalidFrameId)
    }

    fn deallocate_frame(&mut self, fid: FrameId) -> Result<Frame, KError> {
        let (frame, refcnt) = self.frames.get_mut(fid).ok_or(KError::InvalidFrameId)?;
        if *refcnt == 0 {
            frame.take().ok_or(KError::InvalidFrameId)
        } else {
            Err(KError::FrameStillMapped)
        }
    }
}

/// ResumeHandle is the HW specific logic that switches the CPU
/// to the a new entry point by initializing the registers etc.
pub(crate) trait ResumeHandle {
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
pub(crate) trait Executor {
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
    fn finish(self) -> Result<Vec<Frame>, TryReserveError> {
        self.frames
            .into_iter()
            .map(|(_offset, base)| base)
            .try_collect()
    }
}

impl elfloader::ElfLoader for DataSecAllocator {
    fn allocate(
        &mut self,
        load_headers: elfloader::LoadableHeaders,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        for header in load_headers {
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
                KernelAllocator::try_refill_tcache(0, large_pages, MemType::Mem)
                    .expect("Refill didn't work");

                let pcm = per_core_mem();
                let mut pmanager = pcm.mem_manager();
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
    ) -> Result<(), elfloader::ElfLoaderErr> {
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
                            frame_vaddr.as_mut_ptr::<u8>().add(copy_in_frame_start)
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

    fn relocate(
        &mut self,
        entry: &elfloader::Rela<elfloader::P64>,
    ) -> Result<(), elfloader::ElfLoaderErr> {
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
                    return Err(elfloader::ElfLoaderErr::UnsupportedRelocationEntry);
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
pub(crate) fn make_process<P: Process>(binary: &'static str) -> Result<Pid, KError> {
    KernelAllocator::try_refill_tcache(7, 1, MemType::Mem)?;

    // Lookup binary of the process
    let mut mod_file = None;
    if let Some(modules) = crate::KERNEL_ARGS.get().map(|args| &args.modules) {
        for module in modules {
            if module.name() == binary {
                mod_file = Some(module);
            }
        }
    }

    let mod_file = mod_file.ok_or(KError::BinaryNotFound { binary })?;
    info!(
        "binary={} cmdline={} module={:?}",
        binary,
        crate::CMDLINE
            .get()
            .unwrap_or(&CommandLineArguments::default())
            .init_args,
        mod_file
    );

    let elf_module = unsafe {
        elfloader::ElfBinary::new(mod_file.as_slice()).map_err(|_e| KError::UnableToParseElf)?
    };

    // We don't have an offset for non-pie applications (i.e., rump apps)
    let offset = if !elf_module.is_pie() {
        VAddr::zero()
    } else {
        VAddr::from(ELF_OFFSET)
    };

    let mut data_sec_loader = DataSecAllocator {
        offset,
        frames: Vec::try_with_capacity(MAX_WRITEABLE_SECTIONS_PER_PROCESS)?,
    };
    elf_module
        .load(&mut data_sec_loader)
        .map_err(|_e| KError::UnableToLoad)?;
    let data_frames: Vec<Frame> = data_sec_loader.finish()?;
    debug_assert!(
        data_frames.len() <= MAX_WRITEABLE_SECTIONS_PER_PROCESS,
        "TODO(error-handlin): Maybe reject ELF files with more?"
    );

    // Allocate a new process
    nr::NR_REPLICA
        .get()
        .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
            let response = replica.execute_mut(nr::Op::AllocatePid, *token)?;
            if let nr::NodeResult::PidAllocated(pid) = response {
                cnrfs::MlnrKernelNode::add_process(pid)
                    .expect("TODO(error-handling): revert state");
                crate::nrproc::NrProcess::<P>::load(pid, mod_file, data_frames)
                    .expect("TODO(error-handling): revert state properly");
                Ok(pid)
            } else {
                Err(KError::ProcessLoadingFailed)
            }
        })
}

/// Create dispatchers for a given Pid to run on all cores.
///
/// Also make sure they are all using NUMA local memory
pub(crate) fn allocate_dispatchers<P: Process>(pid: Pid) -> Result<(), KError> {
    trace!("Allocate dispatchers");

    let mut create_per_region: ArrayVec<(atopology::NodeId, usize), MAX_NUMA_NODES> =
        ArrayVec::new();

    if atopology::MACHINE_TOPOLOGY.num_nodes() > 0 {
        for node in atopology::MACHINE_TOPOLOGY.nodes() {
            let threads = node.threads().count();
            debug_assert!(!create_per_region.is_full(), "Ensured by for loop range");
            create_per_region.push((node.id, threads));
        }
    } else {
        debug_assert!(!create_per_region.is_full(), "ensured MAX_NUMA_NODES >= 1");
        create_per_region.push((0, atopology::MACHINE_TOPOLOGY.num_threads()));
    }

    for (affinity, to_create) in create_per_region {
        let mut dispatchers_created = 0;
        while dispatchers_created < to_create {
            KernelAllocator::try_refill_tcache(20, 1, MemType::Mem)?;
            let mut frame = {
                let pcm = crate::arch::kcb::per_core_mem();
                pcm.gmanager.unwrap().node_caches[affinity as usize]
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

/// A virtual address that's guaranteed to point somewhere in user-space (e.g.,
/// is below KERNEL_BASE).
#[derive(PartialEq, Clone, Copy, Debug, Hash)]
pub(crate) struct UVAddr {
    inner: VAddr,
}

impl UVAddr {
    pub(crate) fn as_usize(&self) -> usize {
        self.inner.as_usize()
    }

    pub(crate) fn vaddr(&self) -> VAddr {
        self.inner
    }
}

impl TryFrom<VAddr> for UVAddr {
    type Error = KError;
    fn try_from(va: VAddr) -> Result<Self, Self::Error> {
        #[allow(clippy::absurd_extreme_comparisons)]
        if va.as_u64() < KERNEL_BASE {
            Ok(Self { inner: va })
        } else {
            Err(KError::NotAUserVAddr)
        }
    }
}

impl TryFrom<u64> for UVAddr {
    type Error = KError;
    fn try_from(va: u64) -> Result<Self, Self::Error> {
        #[allow(clippy::absurd_extreme_comparisons)]
        if va < KERNEL_BASE {
            Ok(Self { inner: VAddr(va) })
        } else {
            Err(KError::NotAUserVAddr)
        }
    }
}

impl TryFrom<usize> for UVAddr {
    type Error = KError;
    fn try_from(va: usize) -> Result<Self, Self::Error> {
        let va64 = va.try_into().unwrap();
        #[allow(clippy::absurd_extreme_comparisons)]
        if va64 < KERNEL_BASE {
            Ok(Self { inner: VAddr(va64) })
        } else {
            Err(KError::NotAUserVAddr)
        }
    }
}

/// Generic trait to access things that are (potentially) in user-space memory.
///
/// We need a trait because we sometimes write logic that takes slices which are
/// in user-space or kernel-space memory (e.g., rackscale (kernel buffers) and a
/// regular process (user-space buffers) reading from the file-system is one
/// example where typically both ways are needed).
pub trait SliceAccess {
    /// Execute a function `f` passing it a "safe-to-access" reference of the
    /// slice represented by `self`.
    ///
    /// - The implementation should return the Result of `f` if it was
    ///   successful.
    fn read_slice<'a>(&'a self, f: Box<dyn Fn(&'a [u8]) -> KResult<()>>) -> KResult<()>;

    /// Write `buffer` into self.
    ///
    /// - Implementation should return [`KError::InvalidLength`] if
    ///   `buffer.len()` is not equal to `self.len()`.
    fn write_slice(&mut self, buffer: &[u8]) -> KResult<()>;

    /// Write `buffer` into `self` at `offset`.
    ///
    /// - `offset` + `buffer.len()` must be smaller or equal to `self.len()`.
    ///
    /// - Implementation should return an error if the write is out-of-bounds.
    ///   of the buffer represented by `self`.
    fn write_subslice(&mut self, buffer: &[u8], offset: usize) -> KResult<()>;

    /// Returns the length of the buffer represented by `self`.
    fn len(&self) -> usize;
}

impl<const N: usize> SliceAccess for [u8; N] {
    fn read_slice<'a>(&'a self, f: Box<dyn Fn(&'a [u8]) -> KResult<()>>) -> KResult<()> {
        f(self)
    }

    fn write_slice(&mut self, buffer: &[u8]) -> KResult<()> {
        if buffer.len() != self.len() {
            return Err(KError::InvalidLength);
        }
        self.copy_from_slice(buffer);
        Ok(())
    }

    fn write_subslice(&mut self, buffer: &[u8], offset: usize) -> KResult<()> {
        self[offset..(offset + buffer.len())].copy_from_slice(buffer);
        Ok(())
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl SliceAccess for &mut [u8] {
    fn read_slice<'a>(&'a self, f: Box<dyn Fn(&'a [u8]) -> KResult<()>>) -> KResult<()> {
        f(self)
    }

    fn write_slice(&mut self, buffer: &[u8]) -> KResult<()> {
        if buffer.len() != self.len() {
            return Err(KError::InvalidLength);
        }
        self.copy_from_slice(buffer);
        Ok(())
    }

    fn write_subslice(&mut self, buffer: &[u8], offset: usize) -> KResult<()> {
        if self.len() < (offset + buffer.len()) {
            return Err(KError::InvalidOffset);
        }

        self[offset..(offset + buffer.len())].copy_from_slice(buffer);
        Ok(())
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

/// Data copied from a user buffer into a kernel space buffer [`KernArcBuffer`],
/// so to make sure the user-application doesn't have any reference anymore.
///
///
/// This is important sometimes due to replication, for example when writing a
/// file with multiple replicas we don't want user-space to change the memory
/// while we copy the data in the file (and hence end up with inconsistent
/// replicas).
///
/// e.g., Any buffer that goes in the NR/CNR logs should be [`KernArcBuffer`].
#[derive(PartialEq, Clone, Debug)]
pub(crate) struct KernArcBuffer {
    pub buffer: Arc<[u8]>,
}

impl TryFrom<UserSlice> for KernArcBuffer {
    type Error = KError;

    /// Converts a user-slice to a kernel slice.
    fn try_from(user_slice: UserSlice) -> KResult<Self> {
        let buffer = nrproc::NrProcess::<ArchProcess>::userslice_to_arc_slice(user_slice)?;
        Ok(Self { buffer })
    }
}

impl TryFrom<&[u8]> for KernArcBuffer {
    type Error = KError;

    /// Converts a user-slice to a kernel slice.
    fn try_from(slice: &[u8]) -> KResult<Self> {
        // TODO: Panics on OOM, need a `try_new_uninit_slice()` https://github.com/rust-lang/rust/issues/63291
        let mut buffer = Arc::<[u8]>::new_uninit_slice(slice.len());
        let data = Arc::get_mut(&mut buffer).unwrap(); // not shared yet, no panic!
        MaybeUninit::write_slice(data, slice);

        let buffer = unsafe {
            // Safety:
            // - Length == slice.len(): see above
            // - All initialized: plain-old-data, wrote all of slice, see above
            buffer.assume_init()
        };
        Ok(Self { buffer })
    }
}

/// A slice of memory in a process' user-space.
///
/// # Note on performance
/// Creating the user-slice is cheap, doing the actual read/write does many
/// checks upfront that can add overheads. The checks are not cached.
#[derive(PartialEq, Clone, Copy, Debug, Hash)]
pub(crate) struct UserSlice {
    pub pid: Pid,
    base: UVAddr,
    len: usize,
}

impl UserSlice {
    /// Creates a new user-space slice if it references memory that can
    /// potentially belong to the process.
    ///
    /// Returns an error if slice addresses potential kernel memory or null.
    pub(crate) fn new(pid: Pid, base: UVAddr, len: usize) -> KResult<Self> {
        debug_assert!(pid < MAX_PROCESSES, "Invalid PID");
        if len > i32::MAX as usize {
            // Don't allow buffers > 2GB, this is pretty arbitrary (and probably
            // still too big) but at least sets some "bound" on syscall duration
            // in the kernel
            return Err(KError::UserBufferTooLarge);
        }
        if let Some(end) = base.as_usize().checked_add(len)
            && base.as_usize() >= BASE_PAGE_SIZE && end < (KERNEL_BASE as usize) {
                return Ok(UserSlice { pid, base, len });
        }
        Err(KError::InvalidUserBufferArgs)
    }

    /// Like [`UserSlice::new`] but use `u64` for base and `len`, and assume we
    /// want to use `current_pid` for the process.
    ///
    /// Helpful when creating a UserSlice from syscall arguments.
    pub(crate) fn for_current_proc(base: u64, len: u64) -> KResult<Self> {
        let pid = current_pid()?;
        let base = UVAddr::try_from(base)?;
        static_assertions::assert_eq_size!(u64, usize); // If this fails, think about this cast:
        let len = len.try_into().unwrap();

        Self::new(pid, base, len)
    }

    /// Checks if the user-slice is accessible given the mappings installed in
    /// the page-tables of the user-space process.
    ///
    /// # Arguments
    /// - `writeable`: If true check that the user-space program has write
    ///   permission to the region covered by the UserSlice, otherwise check for
    ///   read permission.
    fn is_accessible<P: Process>(&self, process: &P, writeable: bool) -> KResult<()> {
        if self.pid != process.pid() {
            // The pid of the user slice should match the pid of the provided
            // process
            return Err(KError::PidMismatchInProcessArgument);
        }
        if let Ok(pid) = current_pid() && pid != process.pid() {
            // We need to be in the process' address space to copy/write from/to
            // user-space
            //
            // TODO(improvment): An arbitrary limitation as we could just read
            // from the physical identity mappings, though then we'd have to
            // slightly change the function interface: we would probably have to
            // call the closure `f` multiple times for non-consecutive regions
            // (in kernel-physical space), or build a fancy slice-iterator thing
            return Err(KError::NotInRightAddressSpaceForReading);
        }

        let start = self.base.as_usize() & !(BASE_PAGE_SIZE - 1);
        let end = self.base.as_usize() + self.len;

        // TODO(performance): The step_by iterator should increment, by
        // whatever resolve() is telling us we can safely increment (it
        // currently doesn't)
        for tocheck in (start..end).step_by(BASE_PAGE_SIZE) {
            // Make sure we're still in user-space address range:
            let addr_to_check: UVAddr = tocheck.try_into()?;
            // Check that this memory is mapped and readable by user-space:
            let (_paddr, rights) = process.vspace().resolve(addr_to_check.vaddr())?;
            if writeable && !rights.is_writable() {
                return Err(KError::UserPtMissingWriteAccess);
            } else if !writeable && !rights.is_readable() {
                return Err(KError::UserPtMissingReadAccess);
            }
        }

        Ok(())
    }

    /// Run a function `f` that gets a safe-to-access reference of the slice
    /// which points to user-space memory.
    pub(crate) fn with_slice<'a, 'b, P: Process, F, R>(&'a self, process: &'a P, f: F) -> KResult<R>
    where
        F: FnOnce(&'b [u8]) -> KResult<R>,
    {
        self.is_accessible(process, false)?;

        let user_slice = unsafe {
            // Safety:
            // - see `with_slice_mut` for safety arguments
            core::slice::from_raw_parts(self.base.vaddr().as_ptr::<u8>(), self.len)
        };

        with_user_space_access_enabled(|| f(user_slice))
    }

    /// Runs a function `f` that gets a safe-to-access mutable reference of the
    /// slice which points to user-space memory.
    pub fn with_slice_mut<'a, 'b, P: Process, F, R>(&'a self, process: &'a P, f: F) -> KResult<R>
    where
        F: FnOnce(&'b mut [u8]) -> KResult<R>,
    {
        self.is_accessible(process, false)?;

        let user_slice = unsafe {
            // Safety: `from_raw_parts_mut`
            //
            // - The entire memory range of this slice must be contained within
            //   a single allocated object! Slices can never span across
            //   multiple allocated objects: This is something that's tricky to
            //   uphold here since this is an arbitrary slice out of a process'
            //   address-space, if this ends up being a problem we'll have to
            //   use raw pointers.
            //
            // - data must be non-null and aligned even for zero-length slices.
            //   -> this is fine, we only deal with [u8] slice, UVAddr checks
            //   for null.
            //
            // - data must point to len consecutive properly initialized values
            //   of type T -> ok, we interpret as plain-old-data `u8`
            //
            // - The memory referenced by the returned slice must not be
            //   accessed through any other pointer (not derived from the return
            //   value) for the duration of lifetime 'a. Both read and write
            //   accesses are forbidden. -> Again a bit tricky, (and let's not
            //   worry about user-space for now), we can create an alias in the
            //   kernel if we write to the same memory from different cores, as
            //   `with_slice_mut` happens inside of an immutable NR operation. I
            //   guess what we've going for us here is that we never care about
            //   this memory for anything in the kernel.
            //
            // - The total size len * mem::size_of::<T>() of the slice must be
            //   no larger than isize::MAX. -> `u8` is 1 byte, `len` is limited
            //   to `i32::MAX` in constructor
            debug_assert!(self.len <= isize::MAX as usize);
            // In addition:
            // - We are in an immutable NR operation because we have an
            //   immutable reference to the process' address space. This ensures
            //   that no-one modfies the page-tables of the process.
            //
            // - We check that all memory is writable by querying the
            //   page-tables. (see check above)
            //
            // - The CPU is inside of the same address-space as the process
            //   we're trying to read-from. (see check above)
            core::slice::from_raw_parts_mut(self.base.vaddr().as_mut_ptr::<u8>(), self.len)
        };

        with_user_space_access_enabled(|| f(user_slice))
    }

    /// Create a subslice from an existing slice.
    ///
    /// # Panics
    /// If the range of the new slice is out of bounds of the existing slice.
    pub fn subslice(&self, index: core::ops::Range<usize>) -> UserSlice {
        if index.start > self.len || index.end > self.len {
            panic!("UserSlice::subslice: index out of bounds");
        }

        UserSlice {
            base: UVAddr::try_from(self.base.as_usize() + index.start).unwrap(),
            len: index.end - index.start,
            pid: self.pid,
        }
    }
}

impl SliceAccess for UserSlice {
    fn read_slice<'a>(&'a self, f: Box<dyn Fn(&'a [u8]) -> KResult<()>>) -> KResult<()> {
        nrproc::NrProcess::<ArchProcess>::userspace_exec_slice(self, f)
    }

    fn write_slice(&mut self, buffer: &[u8]) -> KResult<()> {
        nrproc::NrProcess::<ArchProcess>::write_to_userspace(self, buffer)?;
        Ok(())
    }

    fn write_subslice(&mut self, buffer: &[u8], offset: usize) -> KResult<()> {
        if self.len() < (offset + buffer.len()) {
            return Err(KError::InvalidOffset);
        }

        self.subslice(offset..(offset + buffer.len()))
            .write_slice(buffer)
    }

    fn len(&self) -> usize {
        self.len
    }
}

/// We can turn a [`UserSlice`] into a [`String`].
///
/// This will safely dereference the slice and copy it into a kernel String.
/// Note that we (currently) need to be in the process' address space to do
/// this, if not this will return an error.
impl TryInto<String> for UserSlice {
    type Error = KError;

    fn try_into(self) -> Result<String, KError> {
        nrproc::NrProcess::<ArchProcess>::read_string_from_userspace(self)
    }
}
