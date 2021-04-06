// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::ops::Add;

use log::trace;
use rawtime::Duration;

use lineup::condvar::CondVar;
use lineup::mutex::Mutex;
use lineup::rwlock::{RwLock, RwLockIntent};
use lineup::tls2::Environment;

use super::{c_int, errno, threads};

const RUMPUSER_MTX_SPIN: i64 = 0x01;
const RUMPUSER_MTX_KMUTEX: i64 = 0x02;

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_init(new_mtx: *mut *mut Mutex, flag: i64) {
    let is_spin = flag & RUMPUSER_MTX_SPIN > 0;
    let is_kmutex = flag & RUMPUSER_MTX_KMUTEX > 0;

    let alloc_mtx: Box<Mutex> = Box::new(Mutex::new_with_flags(is_spin, is_kmutex));
    *new_mtx = Box::into_raw(alloc_mtx);

    trace!("rumpuser_mutex_init {:p} {}", *new_mtx, flag);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_spin_p(mtx: *mut Mutex) {
    (*mtx).is_spin();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_enter(mtx: *mut Mutex) {
    trace!("{:?} rumpuser_mutex_enter {:p}", Environment::tid(), mtx);
    (*mtx).enter();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_enter_nowrap(mtx: *mut Mutex) {
    trace!(
        "{:?} rumpuser_mutex_enter_nowrap {:p}",
        Environment::tid(),
        mtx
    );
    (*mtx).enter_nowrap();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_tryenter(mtx: *mut Mutex) -> c_int {
    trace!("{:?} rumpuser_mutex_tryenter {:p}", Environment::tid(), mtx);
    if (*mtx).try_enter() {
        0
    } else {
        errno::EBUSY
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_exit(mtx: *mut Mutex) {
    trace!("{:?} rumpuser_mutex_exit {:p}", Environment::tid(), mtx);
    (*mtx).exit();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_destroy(mtx: *mut Mutex) {
    trace!("rumpuser_mutex_destroy {:p}", mtx);
    let to_free = Box::from_raw(mtx);
    drop(to_free);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_mutex_owner(mtx: *mut Mutex, lwp: *mut *mut threads::lwp) {
    let owner = (*mtx).owner();
    trace!(
        "{:?} rumpuser_mutex_owner mtx={:p} owner={:p}",
        Environment::tid(),
        mtx,
        owner
    );
    *lwp = owner as *mut threads::lwp;
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_init(rw: *mut *mut RwLock) {
    let alloc_rwlock: Box<RwLock> = Box::new(RwLock::new());
    *rw = Box::into_raw(alloc_rwlock);
    trace!("rumpuser_rw_init {:p}", *rw);
}

fn flag_to_intent(flag: i64) -> RwLockIntent {
    pub const RUMPRWLOCK_RUMPUSER_RW_READER: i64 = 0;
    pub const RUMPRWLOCK_RUMPUSER_RW_WRITER: i64 = 1;

    match flag {
        RUMPRWLOCK_RUMPUSER_RW_READER => RwLockIntent::Read,
        RUMPRWLOCK_RUMPUSER_RW_WRITER => RwLockIntent::Write,
        _ => unreachable!("RwLock didn't understant the intent!"), // TODO
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_enter(flag: i64, rw: *mut RwLock) {
    trace!("{:?} rumpuser_rw_enter {:p}", Environment::tid(), rw);
    (*rw).enter(flag_to_intent(flag));
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_tryenter(flag: i64, rw: *mut RwLock) -> c_int {
    trace!("rumpuser_rw_tryenter {:p}", rw);
    if (*rw).try_enter(flag_to_intent(flag)) {
        0
    } else {
        errno::EBUSY
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_tryupgrade(rw: *mut RwLock) -> c_int {
    trace!("rumpuser_rw_tryupgrade {:p}", rw);
    if (*rw).try_upgrade() {
        0
    } else {
        errno::EBUSY
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_downgrade(rw: *mut RwLock) {
    trace!("rumpuser_rw_downgrade {:p}", rw);
    (*rw).downgrade();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_exit(rw: *mut RwLock) {
    trace!("rumpuser_rw_exit");
    (*rw).exit();
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_destroy(rw: *mut RwLock) {
    trace!("rumpuser_rw_destroy {:p}", rw);
    let to_free = Box::from_raw(rw);
    drop(to_free);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_rw_held(typ: i64, rw: *mut RwLock, rvp: *mut i64) {
    trace!("rumpuser_rw_held {:p}", rw);
    *rvp = (*rw).held(flag_to_intent(typ)) as i64;
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_init(cv: *mut *mut CondVar) {
    let alloc_cv: Box<CondVar> = Box::new(CondVar::new());
    *cv = Box::into_raw(alloc_cv);
    trace!("rumpuser_cv_init {:p}", *cv);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_destroy(cv: *mut CondVar) {
    trace!("rumpuser_cv_destroy {:p}", cv);
    let to_free = Box::from_raw(cv);
    drop(to_free);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_wait(cv: *mut CondVar, mtx: *mut Mutex) {
    trace!(
        "{:?} rumpuser_cv_wait {:p} {:p}",
        lineup::tls2::Environment::tid(),
        cv,
        mtx
    );

    (*cv).wait(&*mtx);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_wait_nowrap(cv: *mut CondVar, mtx: *mut Mutex) {
    trace!(
        "{:?} rumpuser_cv_wait_nowrap {:p} {:p}",
        lineup::tls2::Environment::tid(),
        cv,
        mtx
    );

    /*if lineup::tls2::Environment::tid() == lineup::ThreadId(1)
        && (cv as *const u64) == (0xffffffff81f0ba80 as *const u64)
    {
        crate::panic::backtrace();
    }*/

    (*cv).wait_nowrap(&*mtx);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_timedwait(
    cv: *mut CondVar,
    mtx: *mut Mutex,
    sec: u64,
    nanos: u64,
) -> c_int {
    trace!(
        "{:?} rumpuser_cv_timedwait {:p} {:p} {} {}",
        lineup::tls2::Environment::tid(),
        cv,
        mtx,
        sec,
        nanos
    );
    let d = Duration::from_secs(sec).add(Duration::from_nanos(nanos));
    if (*cv).timed_wait(&*mtx, d) {
        0
    } else {
        trace!("ETIMEDOUT {:p} {:p} {} {}", cv, mtx, sec, nanos);
        errno::ETIMEDOUT
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_signal(cv: *mut CondVar) {
    trace!("rumpuser_cv_signal {:p}", cv);
    (*cv).signal();
    trace!("rumpuser_cv_signal completed {:p}", cv);
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_broadcast(cv: *mut CondVar) {
    trace!("rumpuser_cv_broadcast {:p}", cv);
    (*cv).broadcast();
    trace!("rumpuser_cv_broadcast completed");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_cv_has_waiters(cv: *mut CondVar, waiters: *mut i64) {
    trace!("rumpuser_cv_has_waiters {:p}", cv);
    *waiters = (*cv).has_waiters() as i64;
}
