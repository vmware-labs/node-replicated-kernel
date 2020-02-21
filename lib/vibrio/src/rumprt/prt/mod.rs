//! Runtime support to link with/use libpthread

use core::ptr;

use log::info;

use super::{c_int, c_size_t, c_ssize_t, c_void, lwpid_t};

pub const LWPCTL_CPU_NONE: c_int = -1;
pub const LWPCTL_CPU_EXITED: c_int = -2;
pub const LWPCTL_FEATURE_CURCPU: c_int = 0x0000_0001;
pub const LWPCTL_FEATURE_PCTR: c_int = 0x0000_0002;

type LwpMain = Option<unsafe extern "C" fn(arg: *mut u8) -> *mut u8>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lwpctl {
    pub lc_curcpu: c_int,
    pub lc_pctr: c_int,
}

/// I don't understand why this happens to be separated from `threads.rs` lwp at
/// the moment
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rumprun_lwp {
    /// ID of LWP, should not be pub once threads.rs and stub_lwp.rs is merged
    pub id: lwpid_t,
    /// LWP control state
    pub rl_lwpctl: lwpctl,
}

#[no_mangle]
pub unsafe extern "C" fn rumprun_makelwp(
    start: LwpMain,
    arg: *mut c_void,
    private: *mut c_void,
    stack_base: *mut c_void,
    stack_size: c_size_t,
    flags: usize,
    lid: *mut lwpid_t,
) -> c_int {
    info!(
        "rumprun_makelwp {:p} {:p} {:p}--{} {} {:p}",
        arg, private, stack_base, stack_size, flags, lid
    );

    let free_automatically = false;
    let stack =
        lineup::stack::LineupStack::from_ptr(stack_base as *mut u8, stack_size, free_automatically);

    let s = lineup::tls::Environment::thread();
    s.spawn_with_stack(stack, start, arg as *mut u8);
    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_continue() {
    unreachable!("_lwp_continue");
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_ctl(ctl: c_int, data: *mut *mut lwpctl) -> c_int {
    log::error!("_lwp_ctl ctl={} data={:p}", ctl, data);

    let t = lineup::tls::Environment::thread();
    let lwp = t.rumprun_lwp as *mut rumprun_lwp;
    assert_ne!(lwp, ptr::null_mut());

    *data = &mut (*lwp).rl_lwpctl as *mut lwpctl;

    log::error!("_lwp_ctl is done");
    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_exit() {
    let t = lineup::tls::Environment::thread();
    loop {
        info!("rumpuser_thread_exit {:?}", lineup::tls::Environment::tid());
        t.block();
        unreachable!("_lwp_exit");
    }
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_getprivate() -> *mut c_void {
    let fsbase = x86::current::segmentation::rdfsbase() as *mut c_void;
    log::info!("_lwp_getprivate {:p}", fsbase);
    fsbase
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_kill() {
    unreachable!("_lwp_kill");
}

#[no_mangle]
pub unsafe extern "C" fn ___lwp_park60() {
    unreachable!("___lwp_park60");
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_self() -> lwpid_t {
    log::info!("_lwp_self");

    let t = lineup::tls::Environment::thread();
    let lwp = t.rumprun_lwp as *const rumprun_lwp;
    assert_ne!(lwp, ptr::null());

    info!("lwp is {:p}", lwp);
    info!("lwpid {}", (*lwp).id);
    (*lwp).id
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_setname() {
    unreachable!("_lwp_setname");
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_suspend() {
    unreachable!("_lwp_suspend");
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_unpark(lid: lwpid_t, hint: *const c_void) -> c_int {
    unimplemented!("_lwp_unpark lid={} hint={:p}", lid, hint);
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_unpark_all(
    targets: *const lwpid_t,
    count: c_size_t,
    hint: *const c_void,
) -> c_ssize_t {
    log::error!(
        "_lwp_unpark_all targets={:p} count={} hint={:p}",
        targets,
        count,
        hint
    );

    if !targets.is_null() {
        let mut ret = count;

        for idx in 0..count {
            let lwpid = targets.offset(idx as isize);
            if _lwp_unpark(*lwpid, ptr::null()) != 0 {
                ret -= 1;
            }
        }

        ret as c_ssize_t
    } else {
        // Magic constant copied from rumprun
        1024 as c_ssize_t
    }
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_wakeup() {
    unreachable!("_lwp_wakeup");
}
