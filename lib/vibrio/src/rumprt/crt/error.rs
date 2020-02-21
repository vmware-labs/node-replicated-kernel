//! Runtime support for error handling (i.e., retrieve errno).

use crate::rumprt::c_int;

/// Space to store last encountered error number.
#[no_mangle]
pub static mut _errno: c_int = 0i32;

/// Retrieves a mutable pointer to set the current _errno.
///
/// # TODO
/// This should probably be thread safe?
#[no_mangle]
pub unsafe extern "C" fn __errno() -> *mut c_int {
    //unreachable!("__errno");
    &mut _errno as *mut c_int
}
