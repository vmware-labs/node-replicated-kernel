use super::*;
use crate::alloc::boxed::Box;
use core::ptr;

use lineup::mutex::Mutex;
use lineup::semaphore::Semaphore;
use lineup::tls::Environment;

pub unsafe extern "C" fn sem_alloc(count: c_int) -> *mut lkl_sem {
    let alloc_sem: Box<Semaphore> = Box::new(Semaphore::new(count as isize));
    let sem = Box::into_raw(alloc_sem) as *mut lkl_sem;
    trace!("lkl sem_alloc {:p} count={}", sem, count);

    sem
}

pub unsafe extern "C" fn sem_free(sem: *mut lkl_sem) {
    trace!("lkl sem_free {:p}", sem);
    let to_free = Box::from_raw(sem);
    drop(to_free);
}

pub unsafe extern "C" fn sem_up(sem: *mut lkl_sem) {
    trace!("{:?} lkl sem_up {:p}", Environment::tid(), sem);
    let sem = sem as *mut Semaphore;
    (*sem).up();
}

pub unsafe extern "C" fn sem_down(sem: *mut lkl_sem) {
    trace!("{:?} lkl sem_down {:p}", Environment::tid(), sem);
    let sem = sem as *mut Semaphore;
    (*sem).down();
}

pub unsafe extern "C" fn mutex_alloc(recursive: c_int) -> *mut lkl_mutex {
    let alloc_mtx: Box<Mutex> = Box::new(Mutex::new(false, false));
    let mtx = Box::into_raw(alloc_mtx) as *mut lkl_mutex;
    trace!("lkl mutex_alloc {:p} recursive={}", mtx, recursive);

    mtx
}

pub unsafe extern "C" fn mutex_free(mtx: *mut lkl_mutex) {
    trace!("lkl mutex_free {:p}", mtx);
    let mtx = mtx as *mut Mutex;
    let to_free = Box::from_raw(mtx);
    drop(to_free);
}

pub unsafe extern "C" fn mutex_lock(mtx: *mut lkl_mutex) {
    trace!("{:?} mutex_lock {:p}", Environment::tid(), mtx);
    let mtx = mtx as *mut Mutex;
    (*mtx).enter();
}

pub unsafe extern "C" fn mutex_unlock(mtx: *mut lkl_mutex) {
    trace!("{:?} mutex_unlock {:p}", Environment::tid(), mtx);
    let mtx = mtx as *mut Mutex;
    (*mtx).exit();
}
