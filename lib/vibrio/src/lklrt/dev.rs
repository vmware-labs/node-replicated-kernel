use super::*;
use core::ptr;

pub unsafe extern "C" fn ioremap(addr: c_long, size: c_int) -> *mut c_void {
    trace!("lkl ioremap");
    ptr::null_mut()
}

pub unsafe extern "C" fn iomem_access(
    addr: *const c_void,
    val: *mut c_void,
    size: c_int,
    write: c_int,
) -> c_int {
    trace!("lkl iomem_access");
    0
}
