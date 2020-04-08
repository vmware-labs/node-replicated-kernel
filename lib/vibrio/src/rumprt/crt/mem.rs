//! Memory management functions (mmap, malloc, free et. al.)

use core::alloc::Layout;
use core::ptr;

use crate::rumprt::{c_int, c_size_t, c_void};

use log::{error, info, trace};

const SYS_MMAP: i32 = 197;
const MAP_FAILED: u64 = u64::max_value();

/// Simplified format (hard-coded little endian, 64-bit assumption)
/// that rump/NetBSD expects for a mmap call
#[repr(C)]
pub struct sys_mmap_args {
    pub addr: u64,
    pub len: u64,
    pub prot: u64,
    pub flags: u64,
    pub fd: u64,
    pub padding: u64,
    pub pos: u64,
}

/// Implementes mmap by forwarding it to the rumpkernel.
///
/// `mmap(void *addr, size_t len, int prot, int flags, int fd, off_t pos)`
#[no_mangle]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: c_size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    pos: c_int,
) -> *mut c_void {
    info!(
        "mmap addr={:p} len={} prot={} flags={} fd={} pos={}",
        addr, len, prot, flags, fd, pos
    );
    let args = sys_mmap_args {
        addr: addr as u64,
        len: len as u64,
        prot: prot as u64,
        flags: flags as u64,
        fd: fd as u64,
        padding: 0u64,
        pos: pos as u64,
    };

    extern "C" {
        fn rump_syscall(
            arg: c_int,
            arg_ptr: *const c_void,
            arg_len: usize,
            retvals: *mut u64,
        ) -> c_int;
    }
    //int	rump_syscall(int, void *, size_t, register_t *);

    let mut retval: [u64; 2] = [0, 0];
    let error = rump_syscall(
        SYS_MMAP,
        &args as *const _ as *const c_void,
        core::mem::size_of::<sys_mmap_args>(),
        &mut retval as *mut _ as *mut u64,
    );
    info!("mmap syscall returned {} {:?}", error, retval);

    crate::rumprt::crt::error::_errno = error;
    if error == 0 {
        retval[0] as *mut c_void
    } else {
        MAP_FAILED as *mut c_void
    }
}

/// A separate symbol that goes to `mmap`.
#[no_mangle]
pub unsafe extern "C" fn _mmap(
    addr: *mut c_void,
    len: c_size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    pos: c_int,
) -> *mut c_void {
    mmap(addr, len, prot, flags, fd, pos)
}

#[no_mangle]
pub unsafe extern "C" fn mprotect() {
    error!("mprotect");
}

#[no_mangle]
pub unsafe extern "C" fn munmap() {
    error!("munmap");
}

#[no_mangle]
pub unsafe extern "C" fn mlockall() -> c_int {
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn minherit() -> c_int {
    return 0;
}

/// The msync() system call writes all pages with shared modifications in the
/// specified region of the process's address space back to permanent stor-
/// age, and, if requested, invalidates cached data mapped in the region.
#[no_mangle]
pub unsafe extern "C" fn _sys___msync13() {
    unreachable!("_sys___msync13");
}

/// Implementes malloc using the `alloc::alloc` interface.
///
/// We need to add a header to store the size for the
/// `free` and `realloc` implementation.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: c_size_t) -> *mut u8 {
    trace!("malloc {}", size);

    let allocation_size: u64 = (size + 8) as u64;
    let alignment = 8;

    let ptr = alloc::alloc::alloc(Layout::from_size_align_unchecked(
        allocation_size as usize,
        alignment,
    ));
    if ptr != ptr::null_mut() {
        *(ptr as *mut u64) = allocation_size;
        ptr.offset(8isize)
    } else {
        ptr::null_mut()
    }
}

/// Implements calloc using the `alloc::alloc` interface.
#[no_mangle]
pub unsafe extern "C" fn calloc(nmem: c_size_t, size: c_size_t) -> *mut u8 {
    trace!("calloc {} {}", nmem, size);

    let allocation_size: u64 = ((nmem * size) + 8) as u64;
    let alignment = 8;

    let ptr = alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(
        allocation_size as usize,
        alignment,
    ));
    if ptr != ptr::null_mut() {
        *(ptr as *mut u64) = allocation_size;
        ptr.offset(8isize)
    } else {
        ptr::null_mut()
    }
}

/// Implements `free` through rust the rust `alloc` interface.
///
/// Recovers the size of the block by reading the prepended header.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr == ptr::null_mut() {
        return;
    }
    let allocation_size: u64 = *(ptr.offset(-8) as *mut u64);
    trace!("free ptr {:p} size={}", ptr, allocation_size);
    alloc::alloc::dealloc(
        ptr.offset(-8),
        Layout::from_size_align_unchecked(allocation_size as usize, 8),
    );
}

/// Implements `realloc` through rust the rust `alloc` interface.
///
/// Recovers the size of the block by reading the prepended header.
/// Writes the new size to the front of the new/old pointer.
#[no_mangle]
pub unsafe extern "C" fn realloc(cur_ptr: *mut u8, new_size: c_size_t) -> *mut u8 {
    let (orig_ptr, old_allocation_size) = if cur_ptr == ptr::null_mut() {
        (ptr::null_mut(), 0)
    } else {
        (cur_ptr.offset(-8), *(cur_ptr.offset(-8) as *mut u64))
    };

    trace!(
        "realloc {:p} old_size={} new_size={}",
        cur_ptr,
        old_allocation_size,
        new_size
    );

    let new_allocation_size = new_size + 8;

    let new_ptr = alloc::alloc::realloc(
        orig_ptr,
        Layout::from_size_align_unchecked(old_allocation_size as usize, 8),
        new_allocation_size,
    );

    *(new_ptr as *mut u64) = new_allocation_size as u64;
    new_ptr.offset(8isize)
}
