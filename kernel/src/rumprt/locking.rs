use super::threads;
use super::RumpError;
use super::UPCALL_FNS;
use alloc::boxed::Box;
use alloc::vec::Vec;

#[repr(C)]
#[derive(Debug)]
pub struct rumpuser_mtx {
    waiter: Vec<u64>,
    //lwp: lwp,
    locked: bool,
    owner: u64,
    kthread: u64,
    flags: i64,
}

impl rumpuser_mtx {
    fn new(flags: i64) -> rumpuser_mtx {
        rumpuser_mtx {
            waiter: Vec::with_capacity(24),
            locked: false,
            owner: 0,
            kthread: 0,
            flags: flags,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct rumpuser_cv {
    waiters: Vec<u64>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rumpuser_rw {
    _unused: [u8; 0],
}
pub const RUMPRWLOCK_RUMPUSER_RW_READER: rumprwlock = 0;
pub const RUMPRWLOCK_RUMPUSER_RW_WRITER: rumprwlock = 1;

#[allow(non_camel_case_types)]
pub type rumprwlock = u32;

impl rumpuser_cv {
    fn new() -> rumpuser_cv {
        rumpuser_cv {
            waiters: Vec::with_capacity(24),
        }
    }
}

//#define RUMPUSER_MTX_SPIN	0x01
//#define RUMPUSER_MTX_KMUTEX 	0x02

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_init(new_mtx: *mut *mut rumpuser_mtx, flag: i64) {
    let alloc_mtx: Box<rumpuser_mtx> = Box::new(rumpuser_mtx::new(flag));
    *new_mtx = Box::into_raw(alloc_mtx);
    trace!("rumpuser_mutex_init {:p} {}", *new_mtx, flag);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_enter(mtx: *mut rumpuser_mtx) {
    trace!("rumpuser_mutex_enter {:p}", mtx);
    if rumpuser_mutex_tryenter(mtx) == 0 {
        return;
    } else {
        unreachable!("Locked mutex")
        //let nlocks: u64 = 0;
        //(*UPCALL_FNS).hyp_backend_unschedule(&nlocks, 0);
        //(*UPCALL_FNS).hyp_backend_schedule(nlocks, 0);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_enter_nowrap(mtx: *mut rumpuser_mtx) {
    //trace!("rumpuser_mutex_enter_nowrap");
    if (*mtx).locked == false {
        (*mtx).locked = true;
    } else {
        unreachable!("mutex locked");
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_tryenter(mtx: *mut rumpuser_mtx) -> i64 {
    let _l: *mut threads::lwp = threads::rumpuser_curlwp();
    if (*mtx).locked == false {
        (*mtx).locked = true;
        (*mtx).owner = 1;
        (*mtx).kthread = 1;
        0
    } else {
        RumpError::EBUSY as i64
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_exit(mtx: *mut rumpuser_mtx) {
    //trace!("rumpuser_mutex_exit {:p}", mtx);
    (*mtx).locked = false;
    (*mtx).owner = 0;
    (*mtx).kthread = 0;
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_destroy(mtx: *mut rumpuser_mtx) {
    trace!("rumpuser_mutex_destroy");
    let to_free = Box::from_raw(mtx);
    drop(to_free);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_owner(
    _mtx: *mut rumpuser_mtx,
    lwp: *mut *mut threads::lwp,
) {
    trace!("rumpuser_mutex_owner");
    *lwp = threads::rumpuser_curlwp();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_init(_rw: *mut *mut rumpuser_rw) {
    trace!("rumpuser_rw_init");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_enter(_flag: i64, _rw: *mut rumpuser_rw) {
    trace!("rumpuser_rw_enter");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_tryenter(_flag: i64, _rw: *mut rumpuser_rw) -> i64 {
    trace!("rumpuser_rw_tryenter");

    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_tryupgrade(_rw: *mut rumpuser_rw) -> i64 {
    trace!("rumpuser_rw_tryupgrade");

    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_downgrade(_rw: *mut rumpuser_rw) {
    trace!("rumpuser_rw_downgrade");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_exit(_rw: *mut rumpuser_rw) {
    trace!("rumpuser_rw_exit");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_destroy(_rw: *mut rumpuser_rw) {
    trace!("rumpuser_rw_destroy");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_held(_rwtype: i64, _rw: *mut rumpuser_rw, rvp: *mut i64) {
    trace!("rumpuser_rw_held");
    *rvp = threads::rumpuser_curlwp() as i64;
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_init(cv: *mut *mut rumpuser_cv) {
    let alloc_cv: Box<rumpuser_cv> = Box::new(rumpuser_cv::new());
    *cv = Box::into_raw(alloc_cv);
    trace!("rumpuser_cv_init {:p}", *cv);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_destroy(cv: *mut rumpuser_cv) {
    trace!("rumpuser_cv_destroy");
    let to_free = Box::from_raw(cv);
    drop(to_free);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_wait(cv: *mut rumpuser_cv, mtx: *mut rumpuser_mtx) {
    trace!("rumpuser_cv_wait {:p} {:p}", cv, mtx);

    (*cv).waiters.push(mtx as u64);

    let mut nlocks: u64 = 0;
    trace!("hyp_backend_unschedule");
    (*UPCALL_FNS.unwrap()).hyp_backend_unschedule.unwrap()(0, &mut nlocks, mtx as *mut u64);
    rumpuser_mutex_exit(mtx);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_wait_nowrap(_cv: *mut rumpuser_cv, _mtx: *mut rumpuser_mtx) {
    trace!("rumpuser_cv_wait_nowrap");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_timedwait(
    _cv: *mut rumpuser_cv,
    _mtx: *mut rumpuser_mtx,
    _arg3: i64,
    _arg4: i64,
) -> i64 {
    trace!("rumpuser_cv_timedwait");

    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_signal(cv: *mut rumpuser_cv) {
    trace!(
        "rumpuser_cv_signal {:p} waiter cnt {}",
        cv,
        (*cv).waiters.len()
    );
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_broadcast(_cv: *mut rumpuser_cv) {
    trace!("rumpuser_cv_broadcast");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_has_waiters(_cv: *mut rumpuser_cv, _arg2: *mut i64) {
    trace!("rumpuser_cv_has_waiters");
}
