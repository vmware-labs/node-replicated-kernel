#[allow(non_camel_case_types)]
pub type rumplwpop = u32;

pub const RUMPLWPOP_RUMPUSER_LWP_CREATE: rumplwpop = 0;
pub const RUMPLWPOP_RUMPUSER_LWP_DESTROY: rumplwpop = 1;
pub const RUMPLWPOP_RUMPUSER_LWP_SET: rumplwpop = 2;
pub const RUMPLWPOP_RUMPUSER_LWP_CLEAR: rumplwpop = 3;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lwp {
    _unused: [u8; 0],
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_create(
    _f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
    _arg1: *mut u8,
    _arg2: *const u8,
    _arg3: i64,
    _arg4: i64,
    _arg5: i64,
    _arg6: *mut *mut u8,
) -> i64 {
    debug!("rumpuser_thread_create");
    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_exit() {
    debug!("rumpuser_thread_exit");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_join(_arg1: *mut u8) -> i64 {
    debug!("rumpuser_thread_join");
    0
}

static mut CURRENT_LWP: *mut lwp = 0 as *mut lwp;

#[no_mangle]
pub unsafe extern "C" fn rumpuser_curlwpop(op: rumplwpop, lwp: *mut lwp) -> i64 {
    debug!("rumpuser_curlwpop op={} lwp={:p}", op, lwp);
    if op == RUMPLWPOP_RUMPUSER_LWP_SET {
        CURRENT_LWP = lwp;
    }
    if op == RUMPLWPOP_RUMPUSER_LWP_CLEAR {
        CURRENT_LWP = 0 as *mut lwp;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_curlwp() -> *mut lwp {
    //debug!("rumpuser_curlwp");
    CURRENT_LWP
}
