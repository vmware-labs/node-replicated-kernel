use super::{c_int, c_size_t, c_void, rump_biodone_fn, RumpError};
use cstr_core::CStr;

use log::{error, info, trace};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rumpuser_iovec {
    iov_base: *mut c_void,
    iov_len: c_size_t,
}

/// int rumpuser_open(const char *name, int mode, int *fdp)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_open(name: *const i8, _mode: c_int, _fdp: *const c_int) -> c_int {
    let param_name = CStr::from_ptr(name).to_str().unwrap_or("unknown");
    error!("rumpuser_open {}", param_name);
    unimplemented!();
}

/// int rumpuser_close(int fd)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_close(fd: c_int) -> c_int {
    trace!("rumpuser_close {}", fd);
    unimplemented!();
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

    RumpError::ENOENT as c_int
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
    unimplemented!();
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
    unimplemented!();
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
    unimplemented!();
}

/// int rumpuser_syncfd(int fd, int flags, uint64_t start, uint64_t len)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_syncfd(
    _fd: c_int,
    _flags: c_int,
    _start: u64,
    _len: u64,
) -> c_int {
    unimplemented!();
}
