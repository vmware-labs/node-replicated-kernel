use alloc::boxed::Box;
use alloc::string::String;

use kpi::io::{FileFlags, FileModes};

use crate::arch::process::{current_pid, Ring3Process};
use crate::error::KResult;
use crate::fs::fd::FileDescriptor;
use crate::memory::Frame;
use crate::nrproc;
use crate::process::{KernArcBuffer, UserSlice};
use crate::syscalls::{FsDispatch, ProcessDispatch, SystemCallDispatch};

use super::super::syscall::{Arch86SystemCall, Arch86SystemDispatch, Arch86VSpaceDispatch};
use super::fileops::close::rpc_close;
use super::fileops::delete::rpc_delete;
use super::fileops::getinfo::rpc_getinfo;
use super::fileops::mkdir::rpc_mkdir;
use super::fileops::open::rpc_open;
use super::fileops::rename::rpc_rename;
use super::fileops::rw::{rpc_read, rpc_readat, rpc_write, rpc_writeat};
use super::processops::core::rpc_request_core;
use super::processops::mem::rpc_alloc_physical;
use super::processops::print::rpc_log;

pub(crate) struct Arch86LwkSystemCall {
    pub(crate) local: Arch86SystemCall,
}

impl SystemCallDispatch<u64> for Arch86LwkSystemCall {}
// Use x86 syscall processing for not yet implemented systems:
impl Arch86SystemDispatch for Arch86LwkSystemCall {}
impl Arch86VSpaceDispatch for Arch86LwkSystemCall {}

impl FsDispatch<u64> for Arch86LwkSystemCall {
    fn open(&self, path: UserSlice, flags: FileFlags, modes: FileModes) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;

        let mut client = super::RPC_CLIENT.lock();
        rpc_open(&mut **client, pid, pathstring, flags, modes).map_err(|e| e.into())
    }

    fn read(&self, fd: FileDescriptor, uslice: UserSlice) -> KResult<(u64, u64)> {
        nrproc::NrProcess::<Ring3Process>::userspace_exec_slice_mut(
            uslice,
            Box::try_new(move |ubuf: &mut [u8]| {
                let mut client = super::RPC_CLIENT.lock();
                rpc_read(&mut **client, uslice.pid, fd, ubuf).map_err(|e| e.into())
            })?,
        )
    }

    fn write(&self, fd: FileDescriptor, uslice: UserSlice) -> KResult<(u64, u64)> {
        let kernslice = KernArcBuffer::try_from(uslice)?;
        let mut client = super::RPC_CLIENT.lock();
        rpc_write(&mut **client, uslice.pid, fd, &*kernslice.buffer).map_err(|e| e.into())
    }

    fn read_at(&self, fd: FileDescriptor, uslice: UserSlice, offset: i64) -> KResult<(u64, u64)> {
        nrproc::NrProcess::<Ring3Process>::userspace_exec_slice_mut(
            uslice,
            Box::try_new(move |ubuf: &mut [u8]| {
                let mut client = super::RPC_CLIENT.lock();
                rpc_readat(&mut **client, uslice.pid, fd, ubuf, offset).map_err(|e| e.into())
            })?,
        )
    }

    fn write_at(&self, fd: FileDescriptor, uslice: UserSlice, offset: i64) -> KResult<(u64, u64)> {
        let kernslice = KernArcBuffer::try_from(uslice)?;
        let mut client = super::RPC_CLIENT.lock();
        rpc_writeat(&mut **client, uslice.pid, fd, offset, &*kernslice.buffer).map_err(|e| e.into())
    }

    fn close(&self, fd: FileDescriptor) -> KResult<(u64, u64)> {
        let pid = crate::arch::process::current_pid()?;
        let mut client = super::RPC_CLIENT.lock();
        rpc_close(&mut **client, pid, fd).map_err(|e| e.into())
    }

    fn get_info(&self, path: UserSlice) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;

        let mut client = super::RPC_CLIENT.lock();
        rpc_getinfo(&mut **client, pid, pathstring).map_err(|e| e.into())
    }

    fn delete(&self, path: UserSlice) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;

        let mut client = super::RPC_CLIENT.lock();
        rpc_delete(&mut **client, pid, pathstring).map_err(|e| e.into())
    }

    fn file_rename(&self, oldpath: UserSlice, newpath: UserSlice) -> KResult<(u64, u64)> {
        debug_assert_eq!(
            oldpath.pid, newpath.pid,
            "Rename across processes not supported"
        );
        let pid = oldpath.pid;
        let oldpath: String = oldpath.try_into()?;
        let newpath: String = newpath.try_into()?;

        let mut client = super::RPC_CLIENT.lock();
        rpc_rename(&mut **client, pid, oldpath, newpath).map_err(|e| e.into())
    }

    fn mkdir(&self, path: UserSlice, modes: FileModes) -> KResult<(u64, u64)> {
        let pid = path.pid;
        let pathstring: String = path.try_into()?;

        let mut client = super::RPC_CLIENT.lock();
        rpc_mkdir(&mut **client, pid, pathstring, modes).map_err(|e| e.into())
    }
}

impl ProcessDispatch<u64> for Arch86LwkSystemCall {
    fn log(&self, uslice: UserSlice) -> KResult<(u64, u64)> {
        self.local.log(uslice)?;
        let msg: String = uslice.try_into()?;
        let mut client = super::RPC_CLIENT.lock();
        rpc_log(&mut **client, uslice.pid, msg).map_err(|e| e.into())
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

    fn request_core(&self, core_id: u64, entry_point: u64) -> KResult<(u64, u64)> {
        let mut client = super::RPC_CLIENT.lock();
        let pid = crate::arch::process::current_pid()?;
        rpc_request_core(&mut **client, pid, core_id, entry_point)?;

        self.local.request_core(core_id, entry_point)
    }

    fn allocate_physical(&self, page_size: u64, affinity: u64) -> KResult<(u64, u64)> {
        let mut client = super::RPC_CLIENT.lock();
        let pid = crate::arch::process::current_pid()?;
        let (frame_size, frame_base) = rpc_alloc_physical(&mut **client, pid, page_size, affinity)?;

        // TODO: We can't do this on the remote node right now, so try to do this here
        let frame = Frame {
            base: x86::bits64::paging::PAddr(frame_base),
            size: frame_size as usize,
            affinity: affinity as usize,
        };
        let pid = current_pid()?;
        let fid = nrproc::NrProcess::<Ring3Process>::allocate_frame_to_process(pid, frame)?;
        Ok((fid as u64, frame.base.as_u64()))
        //self.local.allocate_physical(page_size, affinity)
    }

    fn exit(&self, code: u64) -> KResult<(u64, u64)> {
        self.local.exit(code)
    }
}
