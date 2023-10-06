use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use fallible_collections::{FallibleVec, FallibleVecGlobal};
use kpi::io::{FileFlags, FileModes};

use crate::arch::kcb::try_per_core_mem;
use crate::arch::process::{current_pid, Ring3Process};
use crate::error::{KError, KResult};
use crate::fs::fd::FileDescriptor;
use crate::memory::backends::{AllocatorStatistics, GrowBackend, PhysicalPageProvider};
use crate::memory::{vspace::MapAction, Frame, VAddr};
use crate::nrproc;
use crate::process::{KernArcBuffer, UserSlice};
use crate::syscalls::{
    FsDispatch, ProcessDispatch, SystemCallDispatch, SystemDispatch, VSpaceDispatch,
};

use super::super::syscall::{Arch86SystemCall, Arch86SystemDispatch, Arch86VSpaceDispatch};
use super::fileops::close::rpc_close;
use super::fileops::delete::rpc_delete;
use super::fileops::getinfo::rpc_getinfo;
use super::fileops::mkdir::rpc_mkdir;
use super::fileops::open::rpc_open;
use super::fileops::rename::rpc_rename;
use super::fileops::rw::{rpc_read, rpc_readat, rpc_write, rpc_writeat};
use super::processops::allocate_physical::rpc_allocate_physical;
use super::processops::print::rpc_log;
use super::processops::release_core::rpc_release_core;
use super::processops::release_physical::rpc_release_physical;
use super::processops::request_core::rpc_request_core;
use super::systemops::get_hardware_threads::rpc_get_hardware_threads;
use super::CLIENT_STATE;
use crate::arch::rackscale::get_shmem_frames::rpc_get_shmem_frames;

pub(crate) struct Arch86LwkSystemCall {
    pub(crate) local: Arch86SystemCall,
}

impl SystemCallDispatch<u64> for Arch86LwkSystemCall {}

impl VSpaceDispatch<u64> for Arch86LwkSystemCall {
    fn map_mem(&self, base: u64, size: u64) -> Result<(u64, u64), KError> {
        log::debug!("map_mem({:x} {:?})", base, size);

        // Implementation mostly copied from map_generic in x86 syscalls.rs
        let base = VAddr::from(base);
        let pcm = try_per_core_mem().ok_or(KError::KcbUnavailable)?;
        let (bp, lp) = crate::memory::utils::size_to_pages(size as usize);
        let mut frames = Vec::try_with_capacity(bp + lp)?;

        // This is necessary because map_frames -> MemMapFrames seems to assume
        // that base pages follow large pages.
        let mut initial_base_frames = Vec::try_with_capacity(bp)?;

        let pid = current_pid()?;

        let mut total_needed_large_pages = lp;
        let mut total_needed_base_pages = bp;

        // TODO(apihell): This `paddr` is bogus, it will return the PAddr of the
        // first frame mapped but if you map multiple Frames, no chance getting that
        // Better would be a function to request physically consecutive DMA memory
        // or use IO-MMU translation (see also rumpuser_pci_dmalloc)
        // also better to just return what NR replies with...
        let mut paddr = None;
        let mut total_len = 0;

        if total_needed_base_pages > 0 {
            let mut per_process_bp_cache = CLIENT_STATE.per_process_base_pages[pid].lock();
            let base_pages_from_cache = core::cmp::min(
                per_process_bp_cache.free_base_pages(),
                total_needed_base_pages,
            );

            // Take base pages from the per-client, per-pid base page cache is possible
            for _i in 0..base_pages_from_cache {
                let frame = per_process_bp_cache
                    .allocate_base_page()
                    .expect("We ensure there is capabity in the FrameCacheBase above");

                initial_base_frames
                    .try_push(frame)
                    .expect("Can't fail see `try_with_capacity`");
            }

            total_needed_base_pages -= base_pages_from_cache;

            // We'll have to allocate another large page to fulfill the request for base pages
            if total_needed_base_pages > 0 {
                total_needed_large_pages += 1;
            }
        }

        if total_needed_large_pages > 0 {
            // Query controller (DCM) to get frames of shmem
            let mut allocated_frames = rpc_get_shmem_frames(Some(pid), total_needed_large_pages)?;

            for i in 0..lp {
                total_len += allocated_frames[i].size;
                unsafe { allocated_frames[i].zero() };
                frames
                    .try_push(allocated_frames[i])
                    .expect("Can't fail see `try_with_capacity`");
                if paddr.is_none() {
                    paddr = Some(allocated_frames[i].base);
                }
            }

            // Grow base pages
            if total_needed_base_pages > 0 {
                let mut base_page_iter = allocated_frames[lp].into_iter();
                for _i in 0..total_needed_base_pages {
                    let mut frame = base_page_iter
                        .next()
                        .expect("needed base frames should all fit within one large frame");

                    total_len += frame.size;
                    unsafe { frame.zero() };
                    if paddr.is_none() {
                        paddr = Some(frame.base);
                    }
                    frames
                        .try_push(frame)
                        .expect("Can't fail see `try_with_capacity`");
                }

                // Add any remaining base pages to the cache, if there's space.
                let mut per_process_bp_cache = CLIENT_STATE.per_process_base_pages[pid].lock();
                let base_pages_to_save = core::cmp::min(
                    base_page_iter.len(),
                    per_process_bp_cache.spare_base_page_capacity(),
                );

                for _i in 0..base_pages_to_save {
                    let frame = base_page_iter
                        .next()
                        .expect("needed base frames should all fit within one large frame");

                    per_process_bp_cache
                        .grow_base_pages(&[frame])
                        .expect("We ensure not to overfill the FrameCacheBase above.");
                }

                if base_page_iter.len() > 0 {
                    log::debug!(
                    "Losing {:?} base pages of shared memory allocated to process {:?}. Oh well.",
                    base_page_iter.len(),
                    pid,
                );
                }
            }
        }

        // Add initial base pages into frame array. doing this in the end ensures
        // that the order of the frames is large pages and then base pages.
        for f in initial_base_frames {
            total_len += f.size;
            if paddr.is_none() {
                paddr = Some(f.base);
            }
            frames
                .try_push(f)
                .expect("Can't fail see `try_with_capacity`");
        }

        nrproc::NrProcess::<Ring3Process>::map_frames(
            current_pid()?,
            base,
            frames,
            MapAction::write(),
        )
        .expect("Can't map memory");
        log::debug!(
            "map_mem({:x} {:?}) = {:?}",
            base,
            size,
            (paddr.unwrap().as_u64(), total_len as u64)
        );

        Ok((paddr.unwrap().as_u64(), total_len as u64))
    }

    fn map_pmem(&self, base: u64, size: u64) -> Result<(u64, u64), KError> {
        self.local.map_pmem(base, size)
    }

    fn map_device(&self, base: u64, size: u64) -> Result<(u64, u64), KError> {
        self.local.map_device(base, size)
    }

    fn map_frame_id(&self, base: u64, frame_id: u64) -> Result<(u64, u64), KError> {
        self.local.map_frame_id(base, frame_id)
    }

    fn unmap_mem(&self, base: u64) -> Result<(u64, u64), KError> {
        self.local.unmap_mem(base)
    }

    fn unmap_pmem(&self, base: u64) -> Result<(u64, u64), KError> {
        self.local.unmap_pmem(base)
    }

    fn identify(&self, addr: u64) -> Result<(u64, u64), KError> {
        self.local.identify(addr)
    }
}

impl SystemDispatch<u64> for Arch86LwkSystemCall {
    fn get_hardware_threads(&self, vaddr_buf: u64, vaddr_buf_len: u64) -> KResult<(u64, u64)> {
        let pid = current_pid()?;
        rpc_get_hardware_threads(pid, vaddr_buf, vaddr_buf_len).map_err(|e| e.into())
    }

    fn get_stats(&self) -> KResult<(u64, u64)> {
        self.local.get_stats()
    }

    fn get_core_id(&self) -> KResult<(u64, u64)> {
        self.local.get_core_id()
    }
}

impl FsDispatch<u64> for Arch86LwkSystemCall {
    fn open(&self, path: UserSlice, flags: FileFlags, modes: FileModes) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;
        rpc_open(pid, pathstring, flags, modes).map_err(|e| e.into())
    }

    fn read(&self, fd: FileDescriptor, uslice: UserSlice) -> KResult<(u64, u64)> {
        rpc_read(uslice.pid, fd, uslice).map_err(|e| e.into())
    }

    fn write(&self, fd: FileDescriptor, uslice: UserSlice) -> KResult<(u64, u64)> {
        let kernslice = KernArcBuffer::try_from(uslice)?;
        rpc_write(uslice.pid, fd, &*kernslice.buffer).map_err(|e| e.into())
    }

    fn read_at(&self, fd: FileDescriptor, uslice: UserSlice, offset: i64) -> KResult<(u64, u64)> {
        rpc_readat(uslice.pid, fd, uslice, offset)
    }

    fn write_at(&self, fd: FileDescriptor, uslice: UserSlice, offset: i64) -> KResult<(u64, u64)> {
        let kernslice = KernArcBuffer::try_from(uslice)?;
        rpc_writeat(uslice.pid, fd, offset, &*kernslice.buffer).map_err(|e| e.into())
    }

    fn close(&self, fd: FileDescriptor) -> KResult<(u64, u64)> {
        let pid = current_pid()?;
        rpc_close(pid, fd).map_err(|e| e.into())
    }

    fn get_info(&self, path: UserSlice) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;
        rpc_getinfo(pid, pathstring).map_err(|e| e.into())
    }

    fn delete(&self, path: UserSlice) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;
        rpc_delete(pid, pathstring).map_err(|e| e.into())
    }

    fn file_rename(&self, oldpath: UserSlice, newpath: UserSlice) -> KResult<(u64, u64)> {
        debug_assert_eq!(
            oldpath.pid, newpath.pid,
            "Rename across processes not supported"
        );
        let pid = oldpath.pid;
        let oldpath: String = oldpath.try_into()?;
        let newpath: String = newpath.try_into()?;
        rpc_rename(pid, oldpath, newpath).map_err(|e| e.into())
    }

    fn mkdir(&self, path: UserSlice, modes: FileModes) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;
        rpc_mkdir(pid, pathstring, modes).map_err(|e| e.into())
    }
}

impl ProcessDispatch<u64> for Arch86LwkSystemCall {
    fn log(&self, uslice: UserSlice) -> KResult<(u64, u64)> {
        let msg: String = uslice.try_into()?;
        rpc_log(msg).map_err(|e| e.into())
    }

    fn get_vcpu_area(&self) -> KResult<(u64, u64)> {
        self.local.get_vcpu_area()
    }

    fn allocate_vector(&self, vector: u64, core: u64) -> KResult<(u64, u64)> {
        self.local.allocate_vector(vector, core)
    }

    fn get_process_info(&self, vaddr_buf: u64, vaddr_buf_len: u64) -> KResult<(u64, u64)> {
        self.local.get_process_info(vaddr_buf, vaddr_buf_len)
    }

    fn request_core(&self, _core_id: u64, entry_point: u64) -> KResult<(u64, u64)> {
        let pid = current_pid()?;
        rpc_request_core(pid, false, entry_point).map_err(|e| e.into())
    }

    fn release_core(&self, core_id: u64) -> KResult<(u64, u64)> {
        let pid = current_pid()?;
        rpc_release_core(pid, core_id as kpi::system::ThreadId).map_err(|e| e.into())
    }

    fn allocate_physical(&self, page_size: u64, affinity: u64) -> KResult<(u64, u64)> {
        let pid = current_pid()?;
        rpc_allocate_physical(pid, page_size, affinity).map_err(|e| e.into())
    }

    fn release_physical(&self, frame_id: u64) -> KResult<(u64, u64)> {
        let pid = current_pid()?;
        rpc_release_physical(pid, frame_id).map_err(|e| e.into())
    }

    fn exit(&self, code: u64) -> KResult<(u64, u64)> {
        self.local.exit(code)
    }
}
