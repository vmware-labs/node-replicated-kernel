use crate::{ds, SchedControl, Scheduler, ThreadId, ENV};
use core::cell::UnsafeCell;

#[derive(Debug)]
pub struct Mutex {
    inner: UnsafeCell<MutexInner>,
}
unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Mutex {
    pub fn new(is_spin: bool, is_kmutex: bool) -> Mutex {
        Mutex {
            inner: UnsafeCell::new(MutexInner {
                owner: None,
                is_kmutex: is_kmutex,
                is_spin: is_spin,
                waitlist: ds::Vec::with_capacity(Scheduler::MAX_THREADS),
                lwp_ptr: None,
            }),
        }
    }

    pub fn is_kmutex(&self) -> bool {
        let mtx = unsafe { &*self.inner.get() };
        mtx.is_kmutex
    }

    pub fn is_spin(&self) -> bool {
        let mtx = unsafe { &*self.inner.get() };
        mtx.is_spin
    }

    pub fn try_enter(&self, yielder: &mut SchedControl) -> bool {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.try_enter(yielder)
    }

    pub fn enter(&self, yielder: &mut SchedControl) {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.enter(yielder);
    }

    pub fn enter_nowrap(&self, yielder: &mut SchedControl) {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.enter_nowrap(yielder);
    }

    pub fn exit(&self, yielder: &mut SchedControl) {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.exit(yielder);
    }

    pub fn owner(&self) -> u64 {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.owner()
    }
}

#[derive(Debug)]
struct MutexInner {
    owner: Option<ThreadId>,
    waitlist: ds::Vec<ThreadId>,
    is_kmutex: bool,
    is_spin: bool,
    lwp_ptr: Option<u64>,
}

impl MutexInner {
    fn try_enter(&mut self, yielder: &mut SchedControl) -> bool {
        let tid = unsafe { ENV.current_tid().expect("Can't lock without tid.") };
        assert!(self.owner != Some(tid), "Locking mutex against itself.");

        if self.owner.is_none() {
            self.owner = Some(tid);
            self.lwp_ptr = Some((yielder.upcalls.curlwp)());
            true
        } else {
            false
        }
    }

    fn enter(&mut self, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid().expect("Can't lock without tid.") };

        if !self.try_enter(yielder) {
            let mut rid: u64 = 0;
            (yielder.upcalls.deschedule)(&mut rid, None);
            self.waitlist.push(tid);
            yielder.make_unrunnable(tid);
            assert!(self.try_enter(yielder));
            (yielder.upcalls.schedule)(&rid, None)
        }
    }

    fn enter_nowrap(&mut self, yielder: &mut SchedControl) {
        // one VCPU supported, no preemption so it must succeed
        assert!(self.try_enter(yielder));
    }

    fn exit(&mut self, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid() };
        assert!(tid.is_some(), "Need to have scheduler thread");
        assert!(self.owner == tid, "Only owner can exit mutex.");
        self.owner = None;
        self.lwp_ptr = None;

        if !self.waitlist.is_empty() {
            let next = self.waitlist.pop();
            yielder.make_runnable(next.unwrap());
        }
    }

    fn owner(&self) -> u64 {
        self.lwp_ptr.unwrap_or(0)
    }
}

impl Drop for MutexInner {
    fn drop(&mut self) {
        assert!(self.waitlist.is_empty());
        assert!(self.owner.is_none());
        assert!(self.lwp_ptr.is_none());
    }
}

#[test]
fn test_mutex() {
    #[derive(Debug)]
    struct NotAtomicU64 {
        val: UnsafeCell<u64>,
    };

    unsafe impl Send for NotAtomicU64 {}
    unsafe impl Sync for NotAtomicU64 {}

    impl NotAtomicU64 {
        pub fn new() -> NotAtomicU64 {
            NotAtomicU64 {
                val: UnsafeCell::new(0),
            }
        }

        pub fn increment(&self) {
            let val = unsafe { &mut *self.val.get() };
            *val += 1;
        }

        pub fn read(&self) -> u64 {
            let val = unsafe { &mut *self.val.get() };
            *val
        }
    }

    use crate::DEFAULT_UPCALLS;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);
    let mtx = ds::Arc::new(Mutex::new(false, false));
    let m1: ds::Arc<Mutex> = mtx.clone();
    let m2: ds::Arc<Mutex> = mtx.clone();

    let counter = ds::Arc::new(NotAtomicU64::new());
    let counter_1: ds::Arc<NotAtomicU64> = counter.clone();
    let counter_2: ds::Arc<NotAtomicU64> = counter.clone();

    s.spawn(4096, move |mut yielder| {
        for _i in 0..5 {
            m2.enter(&mut yielder);
            assert!(counter_1.read() >= 5);
            counter_1.increment();
            m2.exit(&mut yielder);
        }
    });

    s.spawn(4096, move |mut yielder| {
        for _i in 0..5 {
            m1.enter(&mut yielder);
            assert!(counter_2.read() < 5);
            counter_2.increment();
            m1.exit(&mut yielder);
        }
    });

    for _i in 0..10 {
        s.run();
    }

    assert_eq!(counter.read(), 10, "Mutual exclusion failed.")
}
