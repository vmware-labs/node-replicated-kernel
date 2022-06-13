use alloc::boxed::Box;
use alloc::string::String;

use kpi::io::{FileFlags, FileModes};

use crate::arch::process::Ring3Process;
use crate::error::KResult;
use crate::fs::fd::FileDescriptor;
use crate::nrproc;
use crate::process::UserSlice;
use crate::syscalls::FsDispatch;
use crate::syscalls::SystemCallDispatch;

use super::super::syscall::{Arch86ProcessDispatch, Arch86SystemDispatch, Arch86VSpaceDispatch};
use super::close::rpc_close;
use super::delete::rpc_delete;
use super::getinfo::rpc_getinfo;
use super::mkdir::rpc_mkdir;
use super::open::rpc_open;
use super::rename::rpc_rename;
use super::rw::{rpc_read, rpc_readat, rpc_write, rpc_writeat};

pub(crate) struct Arch86LwkSystemCall;

impl SystemCallDispatch<u64> for Arch86LwkSystemCall {}
// Use x86 syscall processing for not yet implemented systems:
impl Arch86SystemDispatch for Arch86LwkSystemCall {}
impl Arch86ProcessDispatch for Arch86LwkSystemCall {}
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
        let kernslice = crate::process::KernSlice::try_from(uslice)?;
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
        let kernslice = crate::process::KernSlice::try_from(uslice)?;
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
