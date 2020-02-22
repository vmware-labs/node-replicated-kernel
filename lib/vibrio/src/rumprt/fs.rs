use super::errno;
use super::{c_int, c_size_t, c_void, rump_biodone_fn};
use cstr_core::CStr;

use log::{error, trace};

use crate::syscalls::*;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rumpuser_iovec {
    iov_base: *mut c_void,
    iov_len: c_size_t,
}

/// int rumpuser_open(const char *name, int mode, int *fdp)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_open(name: *const i8, mode: c_int, fdp: *mut c_int) -> c_int {
    let param_name = CStr::from_ptr(name).to_str().unwrap_or("unknown");
<<<<<<< HEAD
    error!("rumpuser_open {}", param_name);
    unimplemented!("rumpuser_open");
=======
    match file_open(FileOperation::Open, param_name, 0, mode as u64) {
        Ok(fd) => {
            *fdp = fd as i32;
            return 0;
        }
        Err(_) => {
            return RumpError::EINVAL as i32;
        }
    }
>>>>>>> Call open and close syscall from rumprt.
}

/// int rumpuser_close(int fd)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_close(fd: c_int) -> c_int {
<<<<<<< HEAD
    trace!("rumpuser_close {}", fd);
    unimplemented!("rumpuser_close");
=======
    match file_close(FileOperation::Close, fd as u64) {
        Ok(_) => return 0,
        Err(_) => return RumpError::EBADF as i32,
    }
>>>>>>> Call open and close syscall from rumprt.
}

/// int rumpuser_getfileinfo(const char *name, uint64_t *size, int *type)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_getfileinfo(
    name: *const i8,
    size: *const u64,
    typ: *const c_int,
) -> c_int {
    let param_name = CStr::from_ptr(name).to_str().unwrap_or("unknown");
    trace!("rumpuser_getfileinfo {} {} {}", param_name, *size, *typ);

    errno::ENOENT
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
    _fd: c_int,
    _ruiov: *const rumpuser_iovec,
    _iovlen: c_size_t,
    _off: i64,
    _retv: *const c_size_t,
) -> c_int {
    unimplemented!("rumpuser_iovread");
}

/// int rumpuser_iovwrite(int fd, struct rumpuser_iovec *ruiov, size_t iovlen, int64_t off, size_t *retv)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_iovwrite(
    _fd: c_int,
    _ruiov: *const rumpuser_iovec,
    _iovlen: c_size_t,
    _off: i64,
    _retv: *const c_size_t,
) -> c_int {
    unimplemented!("rumpuser_iovwrite");
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
