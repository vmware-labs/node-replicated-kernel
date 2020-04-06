//! Runtime support to link with/use libpthread

use core::ops::Add;
use core::ptr;

use log::info;

use lineup::tls2::Environment;
use rawtime::{Duration, Instant};

use super::{c_int, c_long, c_size_t, c_ssize_t, c_void, clockid_t, lwpid_t, time_t};

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

/// The `struct timespec` C representation for rust code.
///
/// See also https://netbsd.gw.com/cgi-bin/man-cgi?timespec++NetBSD-8.0
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TimeSpec {
    /// The elapsed time in whole seconds.
    pub tv_sec: time_t,
    /// The rest of the elapsed time in nanoseconds.
    pub tv_nsec: c_long,
}

#[no_mangle]
pub unsafe extern "C" fn rumprun_makelwp(
    start: LwpMain,
    arg: *mut c_void,
    tls_private: *mut c_void,
    stack_base: *mut c_void,
    stack_size: c_size_t,
    flags: usize,
    lid: *mut lwpid_t,
) -> c_int {
    log::error!("TODO what happen to lid");
    info!(
        "rumprun_makelwp {:p} {:p} {:p}--{} {} {:p}",
        arg, tls_private, stack_base, stack_size, flags, lid
    );

    let free_automatically = false;
    let stack =
        lineup::stack::LineupStack::from_ptr(stack_base as *mut u8, stack_size, free_automatically);

    let s = Environment::thread();
    s.spawn_with_args(stack, start, arg as *mut u8, tls_private as *mut lineup::tls2::ThreadControlBlock<'static>);
    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_continue() {
    unreachable!("_lwp_continue");
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_ctl(ctl: c_int, data: *mut *mut lwpctl) -> c_int {
    log::error!("_lwp_ctl ctl={} data={:p}", ctl, data);

    let t = Environment::thread();
    let lwp = t.rumprun_lwp as *mut rumprun_lwp;
    //assert_ne!(lwp, ptr::null_mut());

    *data = &mut (*lwp).rl_lwpctl as *mut lwpctl;

    log::error!("_lwp_ctl is done");
    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_exit() {
    let t = Environment::thread();
    loop {
        info!("rumpuser_thread_exit {:?}", Environment::tid());
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

/// _lwp_park() can be used to synchronize access to resources
/// among multiple light-weight processes.
///
/// See also: https://netbsd.gw.com/cgi-bin/man-cgi?_lwp_park+2+NetBSD-8.0
///
/// It causes the calling LWP to wait interruptably in the "kernel",
/// until one of the following conditions is met:
///
/// * The ts argument is non-NULL, and the time it specifies has passed.
/// The ts time can be an relative interval to wait if the flags argument
/// does not contain `TIMER_ABSTIME` or it can be an absolute time compared
/// to `CLOCK_REALTIME` or `CLOCK_MONOTONIC` depending on the value of the
/// `clock_id` argument.
///
/// * The LWP receives a directed signal posted using `_lwp_kill()`, or is
/// elected to handle a signal on behalf of its containing process.
///
/// * The LWP is awoken by another LWP in the same process that has made a
/// call to `_lwp_wakeup()`.
///
/// * The LWP is awoken by another LWP in the same process that has made a
/// call to `_lwp_unpark()` or `_lwp_unpark_all()`.
///
/// The preferred method to awaken an LWP sleeping as a result of a call to
/// `_lwp_park()` is to make a call to `_lwp_unpark()`, or `_lwp_unpark_all()`.
/// The `_lwp_wakeup()` system call is a more general facility, and requires
/// more resources to execute.
///
/// The optional hint argument specifies the address of object upon which the
/// LWP is synchronizing.  When the hint value is matched between calls to
/// `_lwp_park()` and `_lwp_unpark()` or `_lwp_unpark_all()`, it may reduce the
/// time necessary for the system to resume execution of waiting LWPs.
///
/// The unpark and unparkhint arguments can be used to fold a park operation
/// and unpark operation into a single system call.  If unpark is non-zero,
/// the system will behave as if the following call had been made before the
/// calling thread begins to wait:
///
/// `_lwp_unpark(unpark, unparkhint);`
#[no_mangle]
pub unsafe extern "C" fn ___lwp_park60(
    clock_id: clockid_t,
    flags: c_int,
    ts: *const TimeSpec,
    unpark: lwpid_t,
    hint: *const c_void,
    unpark_hint: *const c_void,
) -> c_int {
    info!(
        "_lwp_park60 clock_id={}, flags={}, ts={:?}, unpark={}, hint={:p}, unpark_hint={:p}",
        clock_id, flags, ts, unpark, hint, unpark_hint
    );

    if unpark > 0 {
        _lwp_unpark(unpark, unpark_hint);
    }

    /*
    TODO:
    if me->rl_no_parking {
        me->rl_no_parking = 0;
        return 0;
    }*/

    if !ts.is_null() {
        unreachable!("___lwp_park60: executing with non-null ts for first time.");
        const TIMER_ABSTIME: c_int = 0x1;

        let sec = (*ts).tv_sec;
        let nanos = (*ts).tv_sec as u64;
        let now_before_sleeping = Instant::now();

        let until = if flags & TIMER_ABSTIME > 0 {
            let future = Instant::from_nanos((sec as u128) * 1_000_000_000 + nanos as u128);
            // TODO(correctness): Checked substraction may be necessary to avoid overflows in case of reordering + IRQs
            future - now_before_sleeping
        } else {
            Duration::from_secs(sec as u64).add(Duration::from_nanos(nanos))
        };

        let wakeup_in = now_before_sleeping + until;
        let t = Environment::thread();
        t.sleep(until);

        if Instant::now() > wakeup_in {
            super::errno::rumpuser_seterrno(super::errno::ETIMEDOUT);
            -1
        } else {
            0
        }
    } else {
        let t = Environment::thread();
        t.block();
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_self() -> lwpid_t {
    log::info!("_lwp_self");

    let t = Environment::thread();
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
