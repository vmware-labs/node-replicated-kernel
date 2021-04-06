// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryInto;

use super::{c_int, c_size_t, c_void, rump_biodone_fn};
use cstr_core::CStr;

use kpi::io::*;
use kpi::FileOperation;

use bitflags::*;
use log::*;

use crate::syscalls::Fs;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rumpuser_iovec {
    iov_base: *mut c_void,
    iov_len: c_size_t,
}

bitflags! {
    pub struct RumpFileFlags:u64 {
        const RUMPUSER_OPEN_RDONLY = 0x0000;
        const RUMPUSER_OPEN_WRONLY = 0x0001;
        const RUMPUSER_OPEN_RDWR = 0x0002;
        const RUMPUSER_OPEN_CREATE = 0x0004;
        const RUMPUSER_OPEN_EXCL = 0x0008;
    }
}

/// int rumpuser_open(const char *name, int mode, int *fdp)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_open(name: *const i8, mode: c_int, fdp: *mut c_int) -> c_int {
    // 'mode' passed by rump are actually the semantic equivalent of flags.
    let mut flags = FileFlags::O_NONE;
    let mode_mode = RumpFileFlags::from_bits_truncate(mode as u64);
    if ((mode_mode & RumpFileFlags::RUMPUSER_OPEN_RDONLY) == RumpFileFlags::RUMPUSER_OPEN_RDONLY) {
        flags = flags | FileFlags::O_RDONLY;
    }
    if ((mode_mode & RumpFileFlags::RUMPUSER_OPEN_WRONLY) == RumpFileFlags::RUMPUSER_OPEN_WRONLY) {
        flags = flags | FileFlags::O_WRONLY;
    }
    if ((mode_mode & RumpFileFlags::RUMPUSER_OPEN_RDWR) == RumpFileFlags::RUMPUSER_OPEN_RDWR) {
        flags = flags | FileFlags::O_RDWR;
    }
    if ((mode_mode & RumpFileFlags::RUMPUSER_OPEN_CREATE) == RumpFileFlags::RUMPUSER_OPEN_CREATE) {
        flags = flags | FileFlags::O_CREAT;
    }
    if ((mode_mode & RumpFileFlags::RUMPUSER_OPEN_EXCL) == RumpFileFlags::RUMPUSER_OPEN_EXCL) {
        error!("Bespin does not support O_EXCL\n");
    }

    // Rump documentation says the 'hypervisor' sets the permissions of all opened files.
    // As a default, we set all files to RW
    match Fs::open(
        name as u64,
        u64::from(flags),
        u64::from(FileModes::S_IRUSR | FileModes::S_IWUSR),
    ) {
        Ok(fd) => {
            *fdp = fd as c_int;
            0
        }
        Err(_) => super::errno::EINVAL as c_int,
    }
}

/// int rumpuser_close(int fd)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_close(fd: c_int) -> c_int {
    match Fs::close(fd as u64) {
        Ok(_) => 0,
        Err(_) => super::errno::EBADF as c_int,
    }
}

/// int rumpuser_getfileinfo(const char *name, uint64_t *size, int *type)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_getfileinfo(
    name: *const i8,
    size: *mut u64,
    typ: *mut c_int,
) -> c_int {
    match Fs::getinfo(name as u64) {
        Ok(fileinfo) => {
            *size = fileinfo.fsize;
            *typ = fileinfo.ftype as i32;
            0
        }
        Err(_) => super::errno::ENOENT as c_int,
    }
}

/// void rumpuser_bio(int fd, int op, void *data, size_t dlen, int64_t off, rump_biodone_fn biodone, void *donearg)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_bio(
    _fd: c_int,
    _op: c_int,
    _data: *const super::c_void,
    _dlen: c_size_t,
    _off: i64,
    _biodone: rump_biodone_fn,
    _done_arg: *const c_void,
) {
    unimplemented!("rumpuser_bio");
}

/// int rumpuser_iovread(int fd, struct rumpuser_iovec *ruiov, size_t iovlen, int64_t off, size_t *retv)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_iovread(
    fd: c_int,
    ruiov: *const rumpuser_iovec,
    iovlen: c_size_t,
    off: i64,
    retv: *mut c_size_t,
) -> c_int {
    match Fs::read_at(
        fd as u64,
        (*ruiov).iov_base as u64,
        (*ruiov).iov_len as u64,
        off,
    ) {
        Ok(len) => {
            *retv = len.try_into().unwrap();
            0
        }
        Err(_) => super::errno::EINVAL as i32,
    }
}

/// int rumpuser_iovwrite(int fd, struct rumpuser_iovec *ruiov, size_t iovlen, int64_t off, size_t *retv)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_iovwrite(
    fd: c_int,
    ruiov: *const rumpuser_iovec,
    iovlen: c_size_t,
    off: i64,
    retv: *mut c_size_t,
) -> c_int {
    match Fs::write_at(
        fd as u64,
        (*ruiov).iov_base as u64,
        (*ruiov).iov_len as u64,
        off,
    ) {
        Ok(len) => {
            *retv = len.try_into().unwrap();
            0
        }
        Err(_) => super::errno::EINVAL as i32,
    }
}

/// int rumpuser_syncfd(int fd, int flags, uint64_t start, uint64_t len)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_syncfd(
    _fd: c_int,
    _flags: c_int,
    _start: u64,
    _len: u64,
) -> c_int {
    unimplemented!("rumpuser_syncfd");
}
