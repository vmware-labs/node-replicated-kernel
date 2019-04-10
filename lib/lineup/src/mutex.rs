use core::cell::UnsafeCell;

use crate::tls::Environment;
use crate::{ds, Scheduler, ThreadId, ThreadState};

use log::*;

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

    pub fn try_enter(&self) -> bool {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.try_enter()
    }

    pub fn enter(&self) {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.enter();
    }

    pub fn enter_nowrap(&self) {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.enter_nowrap();
    }

    pub fn exit(&self) {
        let mtx = unsafe { &mut *self.inner.get() };
        mtx.exit();
    }

    pub fn owner(&self) -> *const u64 {
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
    lwp_ptr: Option<*const u64>,
}

impl MutexInner {
    fn try_enter(&mut self) -> bool {
        let tid = Environment::tid();
        assert!(self.owner != Some(tid), "Locking mutex against itself.");

        if self.owner.is_none() {
            self.owner = Some(tid);
            let thread_state = crate::tls::Environment::thread();
            self.lwp_ptr = Some(thread_state.rump_lwp);
            true
        } else {
            trace!(
                "Mutex {:p} try_enter failed by {:?}, currently owned by {:?}",
                self,
                crate::tls::Environment::tid(),
                self.owner
            );
            false
        }
    }

    fn enter(&mut self) {
        let tid = Environment::tid();
        let yielder: &mut ThreadState = Environment::thread();

        if !self.try_enter() {
            let mut rid = 0;
            trace!("try_enter failed deschedule");
            (yielder.upcalls.deschedule)(&mut rid, None);
            self.waitlist.push(tid);
            yielder.make_unrunnable(tid);
            assert!(self.try_enter());
            (yielder.upcalls.schedule)(&rid, None)
        }
    }

    fn enter_nowrap(&mut self) {
        assert!(
            self.try_enter(),
            "one VCPU supported, no preemption so it must succeed"
        );
    }

    fn exit(&mut self) {
        let tid = Environment::tid();
        let yielder: &mut ThreadState = Environment::thread();

        //assert!(self.owner == Some(tid), "Only owner can exit mutex.");
        self.owner = None;
        self.lwp_ptr = None;

        if !self.waitlist.is_empty() {
            let next = self.waitlist.pop();
            yielder.make_runnable(next.unwrap());
        }
    }

    fn owner(&self) -> *const u64 {
        self.lwp_ptr.unwrap_or(core::ptr::null())
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
    env_logger::init();

    use crate::DEFAULT_UPCALLS;
    use core::ptr;

    let mut s = Scheduler::new(DEFAULT_UPCALLS);
    let mtx = ds::Arc::new(Mutex::new(false, false));
    let m1: ds::Arc<Mutex> = mtx.clone();
    let m2: ds::Arc<Mutex> = mtx.clone();

    s.spawn(
        32 * 4096,
        move |_| {
            assert!(m2.try_enter());
            Environment::thread().relinquish();
            m2.exit();
        },
        ptr::null_mut(),
    );

    s.spawn(
        32 * 4096,
        move |_| {
            assert!(!m1.try_enter());
            m1.enter();
            m1.exit();
        },
        ptr::null_mut(),
    );

    s.run();
}
