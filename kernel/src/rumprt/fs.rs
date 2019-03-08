use super::{c_char, c_int, c_size_t, c_void, rump_biodone_fn, RumpError};
use cstr_core::CStr;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rumpuser_iovec {
    iov_base: *mut c_void,
    iov_len: c_size_t,
}

/// int rumpuser_open(const char *name, int mode, int *fdp)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_open(
    name: *const c_char,
    mode: c_int,
    fdp: *const c_int,
) -> c_int {
    unimplemented!();
}

/// int rumpuser_close(int fd)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_close(fd: c_int) -> c_int {
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
    error!("rumpuser_getfileinfo {}", param_name);

    RumpError::ENOENT as c_int
}

/// void rumpuser_bio(int fd, int op, void *data, size_t dlen, int64_t off, rump_biodone_fn biodone, void *donearg)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_bio(
    fd: c_int,
    op: c_int,
    data: *const super::c_void,
    dlen: c_size_t,
    off: i64,
    biodone: rump_biodone_fn,
    done_arg: *const c_void,
) {
    unimplemented!();
}

/// int rumpuser_iovread(int fd, struct rumpuser_iovec *ruiov, size_t iovlen, int64_t off, size_t *retv)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_iovread(
    fd: c_int,
    ruiov: *const rumpuser_iovec,
    iovlen: c_size_t,
    off: i64,
    retv: *const c_size_t,
) -> c_int {
    unimplemented!();
}

/// int rumpuser_iovwrite(int fd, struct rumpuser_iovec *ruiov, size_t iovlen, int64_t off, size_t *retv)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_iovwrite(
    fd: c_int,
    ruiov: *const rumpuser_iovec,
    iovlen: c_size_t,
    off: i64,
    retv: *const c_size_t,
) -> c_int {
    unimplemented!();
}

/// int rumpuser_syncfd(int fd, int flags, uint64_t start, uint64_t len)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_syncfd(fd: c_int, flags: c_int, start: u64, len: u64) -> c_int {
    unimplemented!();
}
