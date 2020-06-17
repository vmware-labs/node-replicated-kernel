//! Logic for process spawning.
#![allow(unused)]

use alloc::format;
use alloc::vec::Vec;
use core::convert::TryInto;

use crate::arch;
use crate::arch::memory::paddr_to_kernel_vaddr;
use crate::arch::memory::LARGE_PAGE_SIZE;
use crate::arch::process::Ring3Process;
use crate::error::KError;
use crate::kcb;
use crate::memory::KernelAllocator;
use crate::memory::{Frame, PhysicalPageProvider, VAddr};
use crate::prelude::overlaps;
use crate::process::{Executor, Pid, ProcessError};
use crate::{nr, round_up};

/// An elfloader implementation that only loads the writeable sections of the program.
struct DataSecAllocator {
    offset: VAddr,
    frames: Vec<(usize, Frame)>,
    frame_copy_idx: usize,
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
            let elf_vbase = self.offset + *pheader_offset & !(LARGE_PAGE_SIZE - 1);
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
fn make_process(binary: &'static str) -> Result<Pid, KError> {
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
        frame_copy_idx: 0,
    };
    elf_module
        .load(&mut data_sec_loader)
        .map_err(|_e| ProcessError::UnableToLoad)?;
    let data_frames: Vec<Frame> = data_sec_loader.finish();

    // Create a new process
    let replica = kcb.arch.replica.as_ref().expect("Replica not set");
    let response = replica.execute(
        nr::Op::ProcCreate(&mod_file, data_frames),
        kcb.arch.replica_idx,
    )?;

    match response {
        nr::NodeResult::ProcCreated(pid) => Ok(pid),
        _ => unreachable!("Got unexpected response"),
    }
}

/// Create dispatchers for a given Pid to run on all cores.
///
/// Also make sure they are all using NUMA local memory
fn allocate_dispatchers(pid: Pid) -> Result<(), KError> {
    trace!("Allocate dispatchers");

    let mut create_per_region: Vec<(topology::NodeId, usize)> =
        Vec::with_capacity(topology::MACHINE_TOPOLOGY.num_nodes() + 1);

    if topology::MACHINE_TOPOLOGY.num_nodes() > 0 {
        for node in topology::MACHINE_TOPOLOGY.nodes() {
            let threads = node.threads().count();
            create_per_region.push((node.id, threads));
        }
    } else {
        create_per_region.push((0, topology::MACHINE_TOPOLOGY.num_threads()));
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

            let kcb = crate::kcb::get_kcb();
            let replica = kcb.arch.replica.as_ref().expect("Replica not set");
            let response = replica.execute(
                nr::Op::DispatcherAllocation(pid, frame),
                kcb.arch.replica_idx,
            )?;

            match response {
                nr::NodeResult::ExecutorsCreated(how_many) => {
                    assert!(how_many > 0);
                    dispatchers_created += how_many;
                }
                _ => unreachable!("Got unexpected response"),
            };
        }
    }

    debug!("Allocated dispatchers");
    Ok(())
}

/// Spawns a new process
///
/// This function is way too long because of several things that need to happen,
/// and they are currently (TODO) not neatly encapsulated away in modules/functions
/// We're loading a process from a module:
/// - First we are constructing our own custom elfloader trait to load figure out
///   which program headers in the module will be writable (these should not be replicated by NR)
/// - Then we continue by creating a new Process through an nr call
/// - Then we allocate a bunch of memory on all NUMA nodes to create enough dispatchers
///   so we can run on all cores
/// - Finally we allocate a dispatcher to the current core (0) and start running the process
pub fn spawn(binary: &'static str) -> Result<Pid, KError> {
    let kcb = kcb::get_kcb();

    let pid = make_process(binary)?;
    allocate_dispatchers(pid)?;

    // Set current thread to run executor from our process (on the current core)
    let thread = topology::MACHINE_TOPOLOGY.current_thread();
    let (_gtid, _eid) = nr::KernelNode::<Ring3Process>::allocate_core_to_process(
        pid,
        VAddr::from(0xdeadbfffu64), // This VAddr is irrelevant as it is overriden later
        thread.node_id.or(Some(0)),
        Some(thread.id),
    )?;

    Ok(pid)
}

/// Runs the process allocated to the given core.
pub fn schedule() -> ! {
    let kcb = kcb::get_kcb();
    let thread = topology::MACHINE_TOPOLOGY.current_thread();
    let replica = kcb.arch.replica.as_ref().expect("Replica not set");

    // Get an executor
    let response = replica.execute_ro(
        nr::ReadOps::CurrentExecutor(thread.id),
        kcb.arch.replica_idx,
    );
    let executor = match response {
        Ok(nr::NodeResult::Executor(e)) => e,
        e => unreachable!("Got unexpected response {:?}", e),
    };

    info!("Created the init process, about to go there...");
    use alloc::sync::Weak;
    let no = kcb::get_kcb()
        .arch
        .swap_current_process(Weak::upgrade(&executor).unwrap());
    assert!(no.is_none());

    unsafe {
        let rh = kcb::get_kcb().arch.current_process().map(|p| p.start());
        rh.unwrap().resume();
    }
}
