// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime support to link with/use libpthread

use alloc::boxed::Box;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, trace, warn};

use lineup::threads::ThreadId;
use lineup::tls2::Environment;
use spin::Mutex;

use super::{c_int, c_long, c_size_t, c_ssize_t, c_void, clockid_t, lwpid_t, time_t};

pub const LWPCTL_CPU_NONE: c_int = -1;
pub const LWPCTL_CPU_EXITED: c_int = -2;
pub const LWPCTL_FEATURE_CURCPU: c_int = 0x0000_0001;
pub const LWPCTL_FEATURE_PCTR: c_int = 0x0000_0002;

pub const RL_MASK_PARKED: usize = 0x1;
pub const RL_MASK_UNPARK: usize = 0x1;
pub const RL_MASK_PARK: usize = 0x2;

type LwpMain = Option<unsafe extern "C" fn(arg: *mut u8) -> *mut u8>;

static CURLWPID: AtomicI32 = AtomicI32::new(1);

static AVAILABLE_CORES: AtomicUsize = AtomicUsize::new(1);

struct LwpWrapper(NonNull<rumprun_lwp>);
unsafe impl core::marker::Send for LwpWrapper {}
unsafe impl core::marker::Sync for LwpWrapper {}

lazy_static! {
    static ref LWP_HT: spin::Mutex<HashMap<lwpid_t, LwpWrapper>> = Mutex::new(HashMap::new());
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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lwpctl {
    pub lc_curcpu: c_int,
    pub lc_pctr: c_int,
}

/// Meta-data for rumprun / NetBSD pthreads
///
/// I don't understand why this happens to be separated from `threads.rs` lwp at
/// the moment
#[repr(C)]
#[derive(Debug)]
pub struct rumprun_lwp {
    /// ID of LWP, should not be pub once threads.rs and stub_lwp.rs is merged
    pub id: lwpid_t,
    /// LWP control state
    pub rl_lwpctl: lwpctl,
    /// The underlying lineup thread id
    pub rl_thread: ThreadId,
    /// Park status of the LWP
    pub rl_pstatus: AtomicUsize,
    /// Original provided start function of LWP
    pub start: LwpMain,
    /// Original provided argument for `start`
    pub arg: *mut u8,
}

unsafe impl core::marker::Send for rumprun_lwp {}

pub fn context_switch(prev_cookie: *mut u8, next_cookie: *mut u8) {
    //trace!("got context switched {:p} {:p}", prev_cookie, next_cookie);

    let prev: *mut rumprun_lwp = prev_cookie as *mut rumprun_lwp;
    let next: *mut rumprun_lwp = next_cookie as *mut rumprun_lwp;
    unsafe {
        if !prev.is_null() && (*prev).rl_lwpctl.lc_curcpu != LWPCTL_CPU_EXITED {
            (*prev).rl_lwpctl.lc_curcpu = LWPCTL_CPU_NONE;
        }
        if !next.is_null() {
            // Use core_id_to_index to ensure it fits in an i32
            (*next).rl_lwpctl.lc_curcpu =
                lineup::core_id_to_index(Environment::scheduler().core_id) as i32;
            (*next).rl_lwpctl.lc_pctr += 1;
        }
    }
}

extern "C" {
    fn rump_pub_lwproc_curlwp() -> *const c_void;
    fn rump_pub_lwproc_switch(lwp: *const c_void);
    fn rump_pub_lwproc_newlwp(pid: c_int) -> c_int;
    fn getpid() -> c_int;
}

unsafe extern "C" fn rumprun_makelwp_tramp(arg: *mut u8) -> *mut u8 {
    rump_pub_lwproc_switch(arg as *const c_void);
    let lwp = Environment::thread().rumprun_lwp as *const rumprun_lwp;
    (((*lwp).start).unwrap())((*lwp).arg);
    unreachable!("does it exit or not -- hey it probably can?")
}

fn get_my_rumprun_lwp() -> *mut rumprun_lwp {
    Environment::thread().rumprun_lwp as *mut rumprun_lwp
}

fn get_rumprun_lwp_context(lwpid: lwpid_t) -> *const rumprun_lwp {
    LWP_HT
        .lock()
        .get(&lwpid)
        .expect("Can't find state associated with lwpid")
        .0
        .as_ptr()
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
    debug_assert!(!tls_private.is_null(), "TLS area shouldn't be null");
    debug_assert!(!lid.is_null(), "lid shouldn't be null");
    trace!(
        "rumprun_makelwp {:p} {:p} {:p} {:p}--{} {} {:p}",
        start.unwrap(),
        arg,
        tls_private,
        stack_base,
        stack_size,
        flags,
        lid
    );

    let curlwp = rump_pub_lwproc_curlwp();
    let errno = rump_pub_lwproc_newlwp(getpid());
    if errno != 0 {
        return errno;
    }
    assert_eq!(errno, 0);

    let newlwp = rump_pub_lwproc_curlwp();

    let rlid = CURLWPID.fetch_add(1, Ordering::Relaxed);
    let rl: Box<rumprun_lwp> = Box::new(rumprun_lwp {
        id: rlid,
        rl_lwpctl: lwpctl {
            lc_curcpu: 0,
            lc_pctr: 0,
        },
        start,
        arg: arg as *mut u8,
        rl_thread: ThreadId(0),
        rl_pstatus: AtomicUsize::new(RL_MASK_PARK),
    });
    let rl_ptr = Box::leak(rl);

    LWP_HT.lock().insert(
        rlid,
        LwpWrapper(ptr::NonNull::new(rl_ptr).expect("Can't be null")),
    );

    // assignme:
    let tls_private = tls_private as *mut lineup::tls2::ThreadControlBlock<'static>;
    (*tls_private).rumprun_lwp = rl_ptr as *mut _ as *mut u64; // TODO: free it again somewhere

    let free_automatically = false;
    let stack =
        lineup::stack::LineupStack::from_ptr(stack_base as *mut u8, stack_size, free_automatically);

    // XXX: what time should we be doing this?
    rump_pub_lwproc_switch(curlwp);

    let coreid = (rlid as usize) % AVAILABLE_CORES.load(Ordering::Relaxed);
    let hacky_coreid = match rlid as usize {
        2 => 0,
        11 => 1,
        12 => 2,
        13 => 3,
        14 => 4,
        15 => 5,
        _ => coreid,
    };
    let gtid = crate::rumprt::CPUIDX_TO_GTID.lock()[hacky_coreid];
    let tid = Environment::thread().spawn_with_args(
        stack,
        Some(rumprun_makelwp_tramp),
        newlwp as *mut u8,
        gtid,
        None,
        tls_private,
    );
    trace!(
        "rlid={:?}, available_cores={:?} rump_core_id={:?} gtid={:?}, tid={:?}",
        rlid,
        AVAILABLE_CORES.load(Ordering::Relaxed),
        coreid,
        gtid,
        tid
    );

    debug!(
        "rumprun_makelwp spawned {:?} on core {} (gtid={:?})",
        tid, coreid, gtid
    );

    // TODO(smp-correctness): Are we having a race here between new thread accessing
    // rl_thread and us assigning it?
    (*rl_ptr).rl_thread = tid.expect("Didn't create a thread?");
    *lid = rlid;

    // TODO: insert rl_ptr in a list

    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_continue() {
    unreachable!("_lwp_continue");
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_ctl(ctl: c_int, data: *mut *mut lwpctl) -> c_int {
    let t = Environment::thread();
    let lwp = t.rumprun_lwp as *mut rumprun_lwp;
    assert_ne!(lwp, ptr::null_mut());

    *data = (&mut (*lwp).rl_lwpctl) as *mut lwpctl;
    assert_ne!(*data, ptr::null_mut());

    trace!(
        "_lwp_ctl ctl={} data={:p}  set *data to {:p}",
        ctl,
        data,
        *data
    );
    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_exit() {
    let t = Environment::thread();
    loop {
        warn!(
            "_lwp_exit tid={:?} oncore={}",
            Environment::tid(),
            Environment::scheduler().core_id
        );
        t.block();
        unreachable!("_lwp_exit");
    }
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_getprivate() -> *mut c_void {
    let fsbase = x86::current::segmentation::rdfsbase() as *mut c_void;
    trace!("_lwp_getprivate {:p}", fsbase);
    fsbase
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_kill() {
    unreachable!(
        "_lwp_kill on {} core {}",
        Environment::tid(),
        Environment::scheduler().core_id
    );
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
    trace!(
        "_lwp_park60 clock_id={}, flags={}, ts={:?}, unpark={}, hint={:p}, unpark_hint={:p}",
        clock_id,
        flags,
        ts,
        unpark,
        hint,
        unpark_hint
    );

    if unpark > 0 {
        _lwp_unpark(unpark, unpark_hint);
    }

    let me = get_my_rumprun_lwp();
    if (*me).rl_pstatus.swap(RL_MASK_PARKED, Ordering::SeqCst) == RL_MASK_UNPARK {
        // We tried to park but someone else already unparked us again in advance
        // pstatus was set to unpark -- so all we have to do is return
        // from parking immediately
        (*me).rl_pstatus.swap(RL_MASK_PARK, Ordering::SeqCst);
        super::errno::rumpuser_seterrno(super::errno::EALREADY);
        return -1;
    }

    let retval = if !ts.is_null() {
        unreachable!("___lwp_park60: executing with non-null ts for first time.");

        /*const TIMER_ABSTIME: c_int = 0x1;

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
        }*/
    } else {
        let t = Environment::thread();
        trace!(
            "_lwp_park60 about to block tid={:?} lwpid={}",
            Environment::tid(),
            (*get_my_rumprun_lwp()).id
        );
        t.block();
        0
    };

    // Set pstatus to park again (means we will try to park on next ___lwp_park60 call)
    (*me).rl_pstatus.store(RL_MASK_PARK, Ordering::SeqCst);

    retval
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_self() -> lwpid_t {
    let t = Environment::thread();
    let lwp = t.rumprun_lwp as *const rumprun_lwp;
    assert_ne!(lwp, ptr::null());

    trace!("lwp is tcb = {:p} lwp = {:p} lwpid {}", t, lwp, (*lwp).id);
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

/// _lwp_unpark() resumes execution of the light-weight process lwp.
/// The target LWP is assumed to be waiting in the kernel as a result of a
/// call to _lwp_park().  If the target LWP is not currently waiting, it will
/// return immediately upon the next call to _lwp_park().
///
/// See _lwp_park(2) for a description of the hint argument.
#[no_mangle]
pub unsafe extern "C" fn _lwp_unpark(lid: lwpid_t, hint: *const c_void) -> c_int {
    trace!("_lwp_unpark lid {} hint {:p}", lid, hint);
    let rl = get_rumprun_lwp_context(lid);
    if rl.is_null() {
        trace!("_lwp_unpark rl.is_null");
        return -1;
    }

    // If we set the unpark flag and pstatus was 0 (thread has blocked), we need
    // to call scheduler to wake-up the tid
    if (*rl).rl_pstatus.swap(RL_MASK_UNPARK, Ordering::AcqRel) == RL_MASK_PARKED {
        // Unpark only if the callback is complete (scheduled out)
        trace!("_lwp_unpark -> make_runnable {:?}", (*rl).rl_thread);
        Environment::thread().make_runnable((*rl).rl_thread);
    } else {
        // The thread has not yet blocked, we signalled to unpark immediately again
        // by setting the unpark bit
        trace!(
            "_lwp_unpark: set unpark bit for {:?}, dont make runnable",
            (*rl).rl_thread
        );
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn _lwp_unpark_all(
    targets: *const lwpid_t,
    count: c_size_t,
    hint: *const c_void,
) -> c_ssize_t {
    trace!(
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

/// Initialize the LWP sub-system.
#[no_mangle]
pub unsafe extern "C" fn rumprun_lwp_init(available_cores: usize) {
    lazy_static::initialize(&LWP_HT);
    AVAILABLE_CORES.store(available_cores, Ordering::Relaxed);

    let t = lineup::tls2::Environment::thread();
    let mut mainthread = Box::new(rumprun_lwp {
        id: CURLWPID.fetch_add(1, Ordering::Relaxed),
        rl_lwpctl: lwpctl {
            lc_curcpu: 0,
            lc_pctr: 0,
        },
        rl_thread: lineup::tls2::Environment::tid(),
        rl_pstatus: AtomicUsize::new(RL_MASK_PARK),
        start: None,
        arg: ptr::null_mut(),
    });

    let mut mainthread = Box::leak(mainthread);
    let mainthread_ptr = mainthread as *mut rumprun_lwp;
    trace!(
        "mainthread_ptr: {:p} rl_lwpctl {:p}",
        mainthread_ptr,
        &(*mainthread_ptr).rl_lwpctl
    );
    LWP_HT.lock().insert(
        mainthread.id,
        LwpWrapper(ptr::NonNull::new(mainthread_ptr).expect("Can't be null")),
    );
    t.rumprun_lwp = mainthread_ptr as *mut u64;
}
