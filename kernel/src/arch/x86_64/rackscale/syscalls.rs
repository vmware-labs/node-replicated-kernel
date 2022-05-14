use cstr_core::CStr;

use crate::arch::process::{user_virt_addr_valid, UserPtr, UserSlice};
use crate::error::KError;
use crate::kcb::ArchSpecificKcb;
use crate::memory::VAddr;
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

pub struct Arch86LwkSystemCall;

impl SystemCallDispatch<u64> for Arch86LwkSystemCall {}
// Use x86 syscall processing for not yet implemented systems:
impl Arch86SystemDispatch for Arch86LwkSystemCall {}
impl Arch86ProcessDispatch for Arch86LwkSystemCall {}
impl Arch86VSpaceDispatch for Arch86LwkSystemCall {}

impl FsDispatch<u64> for Arch86LwkSystemCall {
    fn open(&self, pathname: u64, flags: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, pathname, 0)?;

        let mut pathname_user_ptr = VAddr::from(pathname);
        let pathname_str_ptr = UserPtr::new(&mut pathname_user_ptr);
        let pathname_cstr = unsafe { CStr::from_ptr(pathname_str_ptr.as_ptr()) };

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_open(client, pid, pathname_cstr.to_bytes_with_nul(), flags, modes).map_err(|e| e.into())
    }

    fn read(&self, fd: u64, buffer: u64, len: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;

        let mut userslice = UserSlice::new(buffer, len as usize);

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_read(client, pid, fd, len, &mut userslice).map_err(|e| e.into())
    }

    fn write(&self, fd: u64, buffer: u64, len: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;

        let kernslice = crate::process::KernSlice::new(buffer, len as usize);
        let buff_ptr = kernslice.buffer.clone();

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_write(client, pid, fd, &buff_ptr).map_err(|e| e.into())
    }

    fn read_at(&self, fd: u64, buffer: u64, len: u64, offset: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;
        let mut userslice = UserSlice::new(buffer, len as usize);

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_readat(client, pid, fd, len, offset as i64, &mut userslice).map_err(|e| e.into())
    }

    fn write_at(&self, fd: u64, buffer: u64, len: u64, offset: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, buffer, len)?;

        let kernslice = crate::process::KernSlice::new(buffer, len as usize);
        let buff_ptr = kernslice.buffer.clone();

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_writeat(client, pid, fd, offset as i64, &buff_ptr).map_err(|e| e.into())
    }

    fn close(&self, fd: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_close(client, pid, fd).map_err(|e| e.into())
    }

    fn get_info(&self, name: u64, info_ptr: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, name, 0)?;

        let mut filename_user_ptr = VAddr::from(name);
        let filename_str_ptr = UserPtr::new(&mut filename_user_ptr);
        let filename_cstr = unsafe { CStr::from_ptr(filename_str_ptr.as_ptr()) };

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_getinfo(client, pid, filename_cstr.to_bytes_with_nul())
            .map(|(ftype, fsize)| {
                use kpi::io::FileInfo;

                let user_ptr = UserPtr::new(&mut VAddr::from(info_ptr));
                unsafe {
                    (*user_ptr.as_mut_ptr::<FileInfo>()).ftype = ftype;
                    (*user_ptr.as_mut_ptr::<FileInfo>()).fsize = fsize;
                }
                (0, 0)
            })
            .map_err(|e| e.into())
    }

    fn delete(&self, name: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, name, 0)?;

        let mut filename_user_ptr = VAddr::from(name);
        let filename_str_ptr = UserPtr::new(&mut filename_user_ptr);
        let filename_cstr = unsafe { CStr::from_ptr(filename_str_ptr.as_ptr()) };

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_delete(client, pid, filename_cstr.to_bytes_with_nul()).map_err(|e| e.into())
    }

    fn file_rename(&self, oldname: u64, newname: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, oldname, 0)?;
        let _r = user_virt_addr_valid(pid, newname, 0)?;

        let mut old_user_ptr = VAddr::from(oldname);
        let old_str_ptr = UserPtr::new(&mut old_user_ptr);
        let old_cstr = unsafe { CStr::from_ptr(old_str_ptr.as_ptr()) };

        let mut new_user_ptr = VAddr::from(newname);
        let new_str_ptr = UserPtr::new(&mut new_user_ptr);
        let new_cstr = unsafe { CStr::from_ptr(new_str_ptr.as_ptr()) };

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_rename(
            client,
            pid,
            old_cstr.to_bytes_with_nul(),
            new_cstr.to_bytes_with_nul(),
        )
        .map_err(|e| e.into())
    }

    fn mkdir(&self, pathname: u64, modes: u64) -> Result<(u64, u64), KError> {
        let kcb = crate::arch::kcb::get_kcb();
        let pid = kcb.arch.current_pid()?;
        let _r = user_virt_addr_valid(pid, pathname, 0)?;

        let mut pathname_user_ptr = VAddr::from(pathname);
        let pathname_str_ptr = UserPtr::new(&mut pathname_user_ptr);
        let pathname_cstr = unsafe { CStr::from_ptr(pathname_str_ptr.as_ptr()) };

        let client = kcb.arch.rpc_client.as_deref_mut().unwrap();
        rpc_mkdir(client, pid, pathname_cstr.to_bytes_with_nul(), modes).map_err(|e| e.into())
    }
}
