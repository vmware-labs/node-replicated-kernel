use crate::rumprt::{c_int, errno};

#[no_mangle]
pub unsafe extern "C" fn _sys_setcontext() -> c_int {
    errno::ENOTSUP
}

#[no_mangle]
pub unsafe extern "C" fn _sys___wait450() -> c_int {
    errno::ENOTSUP
}
