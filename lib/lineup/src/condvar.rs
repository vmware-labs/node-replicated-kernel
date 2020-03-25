use core::cell::UnsafeCell;
use core::ops::Add;
use core::time::Duration;

use log::trace;
use rawtime::Instant;

use crate::mutex::Mutex;
use crate::tls::Environment;
use crate::{ds, Scheduler, ThreadId, ThreadState, YieldRequest};

#[derive(Debug)]
pub struct CondVar {
    inner: UnsafeCell<CondVarInner>,
}

unsafe impl Send for CondVar {}
unsafe impl Sync for CondVar {}

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
    waiters: ds::Vec<ThreadId>,
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
            waiters: ds::Vec::with_capacity(Scheduler::MAX_THREADS),
        }
    }

    fn cv_unschedule(&mut self, mtx: &Mutex, rid: &mut i32) {
        trace!("cv_unschedule");
        let yielder: &mut ThreadState = Environment::thread();
        (yielder.upcalls.deschedule)(rid, Some(mtx));
        mtx.exit();
    }

    fn cv_reschedule(&mut self, mtx: &Mutex, rid: &i32) {
        let yielder: &mut ThreadState = Environment::thread();

        if mtx.is_spin() && mtx.is_kmutex() {
            (yielder.upcalls.schedule)(&rid, Some(mtx));
            mtx.enter_nowrap();
        } else {
            mtx.enter_nowrap();
            (yielder.upcalls.schedule)(&rid, Some(mtx));
        }
    }

    /// SMP: ok
    pub fn wait(&mut self, mtx: &Mutex) {
        let tid = Environment::tid();
        let yielder: &mut ThreadState = Environment::thread();

        let mut rid = 0;
        self.waiters.push(tid);
        self.cv_unschedule(mtx, &mut rid);

        trace!("waiting for {:?}", tid);
        yielder.make_unrunnable(tid);
        self.cv_reschedule(mtx, &rid);
        let r = self.waiters.remove_item(&tid);
        debug_assert!(r.is_none(), "signal/broadcast must remove");
    }

    /// SMP: ok
    pub fn wait_nowrap(&mut self, mtx: &Mutex) {
        let tid = Environment::tid();
        let yielder: &mut ThreadState = Environment::thread();
        trace!("waiters are {:?}", self.waiters);

        self.waiters.push(tid);
        mtx.exit();
        yielder.make_unrunnable(tid);
        mtx.enter_nowrap();
        let r = self.waiters.remove_item(&tid);
        debug_assert!(r.is_none(), "signal/broadcast must remove");
    }

    /// Returns false on time-out, or true if woken up by other event
    /// SMP:ok
    pub fn timed_wait(&mut self, mtx: &Mutex, d: Duration) -> bool {
        let mut rid: i32 = 0;
        let wakup_time = Instant::now().add(d);
        let tid = Environment::tid();

        self.waiters.push(tid);
        self.cv_unschedule(mtx, &mut rid);
        // TODO: if an event wakes us up the scheduler will still wait until
        // the timeout is reached due to the Timeout YieldRequest
        let yielder: &mut ThreadState = Environment::thread();
        yielder.suspend(YieldRequest::Timeout(wakup_time));
        self.cv_reschedule(mtx, &rid);
        self.waiters.remove_item(&tid);

        trace!(
            "cv_reschedule done Instant::now() < wakup_time = {}",
            Instant::now() < wakup_time
        );
        Instant::now() < wakup_time
    }

    // SMP: ok
    pub fn signal(&mut self) {
        // The thread shall own the mutex with which it called
        // pthread_cond_wait() or pthread_cond_timedwait().
        let waking_tid = self.waiters.pop();
        trace!(
            "{:?} CondVarInner.signal {:p} {:?}",
            Environment::tid(),
            self,
            waking_tid
        );

        waking_tid.map(|tid| {
            let yielder: &mut ThreadState = Environment::thread();
            yielder.make_runnable(tid);
        });
    }

    // SMP: ok
    pub fn broadcast(&mut self) {
        // The thread shall own the mutex with which it called
        // pthread_cond_wait() or pthread_cond_timedwait().
        let waiters = self.waiters.clone();
        self.waiters.clear();
        trace!(
            "{:?} CondVarInner.broadcast {:?}",
            Environment::tid(),
            waiters
        );

        let yielder: &mut ThreadState = Environment::thread();
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
    let _r = env_logger::try_init();

    use crate::DEFAULT_UPCALLS;
    use core::ptr;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);

    let cv = ds::Arc::new(CondVar::new());

    let cv1: ds::Arc<CondVar> = cv.clone();
    let cv2: ds::Arc<CondVar> = cv.clone();

    let mtx = ds::Arc::new(Mutex::new(false, true));
    let m2: ds::Arc<Mutex> = mtx.clone();

    s.spawn(
        32 * 4096,
        move |mut yielder| {
            for _i in 0..5 {
                m2.enter();
                cv2.wait(&m2);
                m2.exit();
            }
        },
        ptr::null_mut(),
    );

    s.spawn(
        32 * 4096,
        move |mut yielder| {
            for _i in 0..5 {
                cv1.signal();
                Environment::thread().relinquish();
            }
        },
        ptr::null_mut(),
    );

    s.run();
}
