use crate::mutex::Mutex;
use crate::{ds, SchedControl, Scheduler, ThreadId, ENV};
use core::cell::UnsafeCell;
use core::time::Duration;
use log::trace;

#[derive(Debug)]
struct CondVar {
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

    pub fn wait(&self, mtx: &Mutex, yielder: &mut SchedControl) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.wait(mtx, yielder);
    }

    pub fn wait_nowrap(&self, mtx: &Mutex, yielder: &mut SchedControl) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.wait_nowrap(mtx, yielder);
    }

    pub fn timed_wait(&self, mtx: &Mutex, d: Duration) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.timed_wait(mtx, d);
    }

    pub fn signal(&self, yielder: &mut SchedControl) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.signal(yielder);
    }

    pub fn broadcast(&self, yielder: &mut SchedControl) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.broadcast(yielder);
    }

    pub fn has_waiters(&self) {
        let cv = unsafe { &mut *self.inner.get() };
        cv.has_waiters();
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

    fn cv_unschedule(&mut self, mtx: &Mutex, rid: &mut u64, yielder: &mut SchedControl) {
        (yielder.upcalls.schedule)(&rid, Some(mtx));

        mtx.exit(yielder);
    }

    fn cv_reschedule(&mut self, mtx: &Mutex, rid: &u64, yielder: &mut SchedControl) {
        if mtx.is_spin() || mtx.is_kmutex() {
            (yielder.upcalls.schedule)(&rid, Some(mtx));
            mtx.enter_nowrap(yielder);
        } else {
            mtx.enter_nowrap(yielder);
            (yielder.upcalls.schedule)(&rid, Some(mtx));
        }
    }

    pub fn wait(&mut self, mtx: &Mutex, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid().expect("Need tid set.") };

        let mut rid: u64 = 0;
        self.cv_unschedule(mtx, &mut rid, yielder);
        self.waiters.push(tid);
        trace!("waiting for {:?}", tid);
        yielder.make_unrunnable(tid);
        self.cv_reschedule(mtx, &rid, yielder);
    }

    pub fn wait_nowrap(&mut self, mtx: &Mutex, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid().expect("Need tid set.") };

        mtx.exit(yielder);
        self.waiters.push(tid);
        yielder.make_unrunnable(tid);
        mtx.enter(yielder);
    }

    pub fn timed_wait(&mut self, _mutex: &Mutex, _d: Duration) {
        unreachable!("CV timedwaits")
    }

    pub fn signal(&mut self, yielder: &mut SchedControl) {
        let waking_tid = self.waiters.pop();
        waking_tid.map(|tid| {
            yielder.make_runnable(tid);
        });
    }

    pub fn broadcast(&mut self, yielder: &mut SchedControl) {
        let waiters = self.waiters.clone();
        self.waiters.clear();
        yielder.make_all_runnable(waiters);
    }

    pub fn has_waiters(&self) -> bool {
        !self.waiters.is_empty()
    }
}

#[test]
fn test_condvar() {
    use crate::DEFAULT_UPCALLS;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);

    let cv = ds::Arc::new(CondVar::new());

    let cv1: ds::Arc<CondVar> = cv.clone();
    let cv2: ds::Arc<CondVar> = cv.clone();

    let mtx = ds::Arc::new(Mutex::new(false, false));
    let m2: ds::Arc<Mutex> = mtx.clone();

    s.spawn(4096, move |mut yielder| {
        for _i in 0..12 {
            cv1.signal(&mut yielder);
        }
    });

    s.spawn(4096, move |mut yielder| {
        for _i in 0..5 {
            m2.enter(&mut yielder);
            cv2.wait(&m2, &mut yielder);
            m2.exit(&mut yielder);
        }
    });

    for _run in 0..100 {
        s.run();
    }
}
