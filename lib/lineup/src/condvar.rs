// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ops::Add;
use core::ptr;
use core::sync::atomic::Ordering;
use core::time::Duration;

use log::trace;
use rawtime::Instant;

use crate::mutex::Mutex;
use crate::threads::{ThreadId, YieldRequest};
use crate::tls2::{Environment, ThreadControlBlock};

fn remove_item<V>(vec: &mut Vec<V>, item: &V) -> Option<V>
where
    V: PartialEq,
{
    let pos = vec.iter().position(|x| *x == *item)?;
    Some(vec.remove(pos))
}

#[derive(Debug)]
pub struct CondVar {
    inner: UnsafeCell<CondVarInner>,
}

unsafe impl Send for CondVar {}
unsafe impl Sync for CondVar {}

impl Default for CondVar {
    fn default() -> Self {
        Self::new()
    }
}

impl CondVar {
    pub fn new() -> CondVar {
        CondVar {
            inner: UnsafeCell::new(CondVarInner::new()),
        }
    }

    pub fn wait(&self, mtx: &Mutex) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.wait(mtx);
    }

    pub fn wait_nowrap(&self, mtx: &Mutex) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.wait_nowrap(mtx);
    }

    // Returns false on time out
    pub fn timed_wait(&self, mtx: &Mutex, d: Duration) -> bool {
        let cv = unsafe { &mut *self.inner.get() };
        cv.timed_wait(mtx, d)
    }

    pub fn signal(&self) {
        trace!("CondVar signal {:p}", self);
        let cv = unsafe { &mut *self.inner.get() };
        cv.signal();
    }

    pub fn broadcast(&self) {
        trace!("{:?} CondVar broadcast {:p}", Environment::tid(), self);
        let cv = unsafe { &mut *self.inner.get() };
        cv.broadcast();
    }

    pub fn has_waiters(&self) -> bool {
        let cv = unsafe { &mut *self.inner.get() };
        cv.has_waiters()
    }
}

#[derive(Debug)]
struct CondVarInner {
    waiters: Vec<ThreadId>,
    /// This is pretty bad and can lead to unsafe memory accesses
    /// in the general case (mutex goes away before cv etc.)
    /// but helps to verify some sanity assertions about
    /// correct CV usage.
    dbg_mutex: *const Mutex,
}

impl Drop for CondVarInner {
    fn drop(&mut self) {
        assert!(
            self.waiters.is_empty(),
            "Can't have outstanding waiters on CV"
        );
    }
}

impl CondVarInner {
    pub fn new() -> CondVarInner {
        CondVarInner {
            waiters: Vec::with_capacity(crate::scheduler::SmpScheduler::MAX_THREADS),
            dbg_mutex: ptr::null(),
        }
    }

    fn cv_unschedule(&mut self, mtx: &Mutex, rid: &mut i32) {
        trace!("cv_unschedule");
        let yielder: &mut ThreadControlBlock = Environment::thread();
        (yielder.upcalls.deschedule)(rid, Some(mtx));
        mtx.exit();
    }

    fn cv_mutex_enter(&mut self, mtx: &Mutex) {
        if mtx.is_spin() {
            trace!("cv_mutex_enter is_spin path");
            mtx.enter_nowrap();
        } else {
            assert!(mtx.is_kmutex());
            mtx.enter_nowrap();
        }
    }

    fn cv_schedule_enter(&mut self, mtx: &Mutex, rid: &i32) {
        let yielder: &mut ThreadControlBlock = Environment::thread();

        if mtx.is_spin() && mtx.is_kmutex() {
            (yielder.upcalls.schedule)(rid, Some(mtx));
            mtx.enter_nowrap();
        } else {
            self.cv_mutex_enter(mtx);
            (yielder.upcalls.schedule)(rid, Some(mtx));
        }
    }

    pub fn wait(&mut self, mtx: &Mutex) {
        let tid = Environment::tid();
        let yielder: &mut ThreadControlBlock = Environment::thread();
        self.dbg_mutex = mtx as *const Mutex;

        let mut rid = 0;
        // TODO(smp): Similar race as in Mutex here:
        // (if we push -> run again on other core -> unschedule in here)
        // not problematic as long as dont support thread stealing...
        self.waiters.push(tid);
        trace!("cv.wait(): make unrunnable {:?} {:p}", tid, mtx.owner());

        self.cv_unschedule(mtx, &mut rid);
        yielder.make_unrunnable(tid);
        self.cv_schedule_enter(mtx, &rid);

        let r = remove_item(&mut self.waiters, &tid);
        debug_assert!(r.is_none(), "signal/broadcast must remove");
    }

    pub fn wait_nowrap(&mut self, mtx: &Mutex) {
        let tid = Environment::tid();
        let yielder: &mut ThreadControlBlock = Environment::thread();
        trace!(
            "{:?} wait_nwrap: {:p} waiters are {:?}",
            Environment::tid(),
            self,
            self.waiters
        );
        self.dbg_mutex = mtx as *const Mutex;

        // TODO(smp): Same issue as in `wait` here:
        self.waiters.push(tid);
        mtx.exit();
        yielder.make_unrunnable(tid);
        mtx.enter_nowrap();

        let r = remove_item(&mut self.waiters, &tid);
        debug_assert!(r.is_none(), "signal/broadcast must remove");
    }

    /// Returns false on time-out, or true if woken up by other event
    pub fn timed_wait(&mut self, mtx: &Mutex, d: Duration) -> bool {
        let mut rid: i32 = 0;
        let wakup_time = Instant::now().add(d);
        let tid = Environment::tid();
        self.dbg_mutex = mtx as *const Mutex;

        self.waiters.push(tid);
        self.cv_unschedule(mtx, &mut rid);
        // TODO: if an event wakes us up the scheduler will still wait until
        // the timeout is reached due to the Timeout YieldRequest
        let yielder: &mut ThreadControlBlock = Environment::thread();
        yielder.suspend(YieldRequest::Timeout(wakup_time));
        self.cv_schedule_enter(mtx, &rid);
        remove_item(&mut self.waiters, &tid);

        trace!(
            "timed_wait: cv_schedule_enter done Instant::now() < wakup_time = {}",
            Instant::now() < wakup_time
        );
        Instant::now() < wakup_time
    }

    /// TODO(smp): see comment
    pub fn signal(&mut self) {
        // The pthread_cond_broadcast() or pthread_cond_signal()
        // functions may be called by a thread whether or not it
        // currently owns the mutex
        unsafe {
            // We don't support this at the moment
            debug_assert!(
                self.dbg_mutex.is_null()
                    || ((*self.dbg_mutex).owner().is_null()
                        || (*self.dbg_mutex).owner()
                            == Environment::thread().rump_lwp.load(Ordering::SeqCst))
            );
        }

        let waking_tid = self.waiters.pop();
        trace!(
            "{:?} CondVarInner.signal {:p} {:?}",
            Environment::tid(),
            self,
            waking_tid
        );

        if let Some(tid) = waking_tid {
            let yielder: &mut ThreadControlBlock = Environment::thread();
            yielder.make_runnable(tid);
        };
    }

    // SMP: not ok!
    pub fn broadcast(&mut self) {
        // The pthread_cond_broadcast() or pthread_cond_signal()
        // functions may be called by a thread whether or not it
        // currently owns the mutex
        unsafe {
            // We don't support this at the moment
            debug_assert!(
                self.dbg_mutex.is_null()
                    || ((*self.dbg_mutex).owner().is_null()
                        || (*self.dbg_mutex).owner()
                            == Environment::thread().rump_lwp.load(Ordering::SeqCst))
            );
        }

        let waiters = self.waiters.clone();
        self.waiters.clear();
        trace!(
            "{:?} CondVarInner.broadcast {:p} {:?}",
            Environment::tid(),
            self,
            waiters
        );

        let yielder: &mut ThreadControlBlock = Environment::thread();
        if !waiters.is_empty() {
            yielder.make_all_runnable(waiters);
        }
    }

    pub fn has_waiters(&self) -> bool {
        !self.waiters.is_empty()
    }
}

#[test]
fn test_condvar() {
    use alloc::sync::Arc;
    use core::ptr;

    use crate::scheduler::SmpScheduler;
    use crate::tls2::SchedulerControlBlock;

    let _r = env_logger::try_init();

    let s: SmpScheduler = Default::default();
    let cv = Arc::new(CondVar::new());

    let cv1: Arc<CondVar> = cv.clone();
    let cv2: Arc<CondVar> = cv.clone();

    let mtx = Arc::new(Mutex::new_kmutex());
    let m2: Arc<Mutex> = mtx.clone();

    s.spawn(
        crate::stack::DEFAULT_STACK_SIZE_BYTES,
        move |_yielder| {
            for _i in 0..5 {
                m2.enter();
                cv2.wait(&m2);
                m2.exit();
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    s.spawn(
        crate::stack::DEFAULT_STACK_SIZE_BYTES,
        move |_yielder| {
            for _i in 0..5 {
                cv1.signal();
                Environment::thread().relinquish();
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    s.run(&scb);
}

/// A simple multi-producer/multi-consumer test using conditional variables.
///
/// We test that we consume the correct amount of produced elements by
/// keeping track of a sum of everything seen so far.
#[cfg(test)]
#[test]
fn test_condvar_smp() {
    use alloc::sync::Arc;
    use core::ptr;
    use std::thread;

    use rawtime::Instant;

    use crate::scheduler::SmpScheduler;
    use crate::stack::DEFAULT_STACK_SIZE_BYTES;
    use crate::tls2::SchedulerControlBlock;

    // Silly unsafe cell that is sync to test mutual exclusion of
    // mutex
    struct UnsafeSyncCell<T: ?Sized> {
        inner: UnsafeCell<T>,
    }
    impl<T> UnsafeSyncCell<T> {
        fn new(v: T) -> Self {
            UnsafeSyncCell {
                inner: UnsafeCell::new(v),
            }
        }
    }
    unsafe impl<T: ?Sized + Send> Send for UnsafeSyncCell<T> {}
    unsafe impl<T: ?Sized + Send> Sync for UnsafeSyncCell<T> {}

    let _r = env_logger::try_init();

    let corecnt = 3;
    let producer = 3;
    let consumer = 4;

    let s: Arc<SmpScheduler> = Default::default();
    let mtx = Arc::new(Mutex::new_spin());
    let more = Arc::new(CondVar::new());
    let less = Arc::new(CondVar::new());

    // A counter to test the mutex
    const BATCH_SIZE: isize = 32;
    let buf: Arc<UnsafeSyncCell<[isize; BATCH_SIZE as usize]>> =
        Arc::new(UnsafeSyncCell::new([0; BATCH_SIZE as usize]));
    let occupied: Arc<UnsafeSyncCell<isize>> = Arc::new(UnsafeSyncCell::new(0));
    let nextin: Arc<UnsafeSyncCell<isize>> = Arc::new(UnsafeSyncCell::new(0));
    let nextout: Arc<UnsafeSyncCell<isize>> = Arc::new(UnsafeSyncCell::new(0));

    // To verify correctness
    let aggregate_counter: Arc<UnsafeSyncCell<isize>> = Arc::new(UnsafeSyncCell::new(0));

    // spawn producer
    for idx in 0..producer {
        let mtx: Arc<Mutex> = mtx.clone();
        let more = more.clone();
        let less = less.clone();
        let nextin = nextin.clone();
        let occupied = occupied.clone();
        let buf = buf.clone();

        log::trace!("spawn producer {} on {}", idx, idx % corecnt);
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                for i in 0..1000 {
                    mtx.enter();
                    unsafe {
                        while *occupied.inner.get() >= BATCH_SIZE {
                            less.wait(&mtx);
                        }
                        assert!(*occupied.inner.get() < BATCH_SIZE);
                        let buf = buf.inner.get();
                        (*buf)[*nextin.inner.get() as usize] = i;

                        *nextin.inner.get() += 1;
                        *nextin.inner.get() = *nextin.inner.get() % BATCH_SIZE;
                        *occupied.inner.get() += 1;
                    }
                    more.signal();
                    mtx.exit();
                }
            },
            ptr::null_mut(),
            idx % corecnt,
            None,
        );
    }

    // spawn consumer
    for idx in 0..consumer {
        let mtx: Arc<Mutex> = mtx.clone();
        let aggregate_counter = aggregate_counter.clone();
        let more = more.clone();
        let less = less.clone();
        let nextout = nextout.clone();
        let occupied = occupied.clone();
        let buf = buf.clone();

        log::trace!("spawn consumer {} on {}", idx, idx % corecnt);
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                for _i in 0..1000 {
                    mtx.enter();
                    unsafe {
                        while *occupied.inner.get() <= 0 {
                            more.wait(&mtx);
                        }
                        assert!(*occupied.inner.get() > 0);
                        let buf = buf.inner.get();
                        let element = (*buf)[*nextout.inner.get() as usize];

                        *aggregate_counter.inner.get() += element;

                        *nextout.inner.get() += 1;
                        *nextout.inner.get() = *nextout.inner.get() % BATCH_SIZE;
                        *occupied.inner.get() -= 1;
                    }
                    less.signal();
                    mtx.exit();
                }
            },
            ptr::null_mut(),
            idx % corecnt,
            None,
        );
    }

    let mut cores = Vec::with_capacity(corecnt);
    for idx in 0..corecnt {
        let s1 = s.clone();
        cores.push(thread::spawn(move || {
            let scb: SchedulerControlBlock = SchedulerControlBlock::new(idx);
            let start = Instant::now();
            while start.elapsed().as_secs() < 1 {
                s1.run(&scb);
            }
        }));
    }

    for c in cores {
        let _r = c.join().unwrap();
    }

    // \sum 0..1000: i
    let expected_aggregate = (999 * (999 + 1)) / 2;
    unsafe {
        assert_eq!(
            producer * expected_aggregate,
            *aggregate_counter.inner.get() as usize
        );
    }
    // Silly method to avoid panic due to dropping unfinished generators
    // (consumer threads may be blocked inside a wait condition once consumers are done)
    // TODO(fix): Should probably have some sort of kill API for threads...
    core::mem::forget(s);
}
