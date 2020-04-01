use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{spin_loop_hint, AtomicUsize, Ordering};

use crate::threads::ThreadId;
use crate::tls2::{Environment, ThreadControlBlock};

use crossbeam_utils::CachePadded;
use log::*;

#[derive(Debug)]
pub struct Mutex {
    inner: UnsafeCell<MutexInner>,
}
unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Mutex {
    pub fn new_spin_kmutex() -> Self {
        Mutex::new_with_flags(true, true)
    }

    pub fn new_kmutex() -> Self {
        Mutex::new_with_flags(false, true)
    }

    pub fn new_spin() -> Self {
        Mutex::new_with_flags(true, false)
    }

    pub fn new() -> Self {
        Mutex::new_with_flags(false, false)
    }

    pub fn new_with_flags(is_spin: bool, is_kmutex: bool) -> Mutex {
        Mutex {
            inner: UnsafeCell::new(MutexInner {
                owner: None,
                is_kmutex,
                is_spin,
                waitlist: Vec::with_capacity(crate::scheduler::SmpScheduler::MAX_THREADS),
                lwp_ptr: None,
                counter: CachePadded::new(AtomicUsize::new(0)),
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
    waitlist: Vec<ThreadId>,
    is_kmutex: bool,
    is_spin: bool,
    lwp_ptr: Option<*const u64>,
    counter: CachePadded<AtomicUsize>,
}

impl MutexInner {
    fn try_enter(&mut self) -> bool {
        let tid = Environment::tid();
        assert!(self.owner != Some(tid), "Locking mutex against itself.");

        let counter = self.counter.load(Ordering::Relaxed);
        loop {
            if counter != 0 {
                // Lock currently held by another thread
                trace!(
                    "Mutex {:p} try_enter failed by {:?}, currently owned by {:?}",
                    self,
                    Environment::tid(),
                    self.owner
                );
                return false;
            }

            // Try to acquire it (set to 1):
            if self.counter.compare_and_swap(0, 1, Ordering::Relaxed) == 0 {
                // we hold the lock now
                break;
            }
            // else: failed to acquire, retry
        }

        let thread_state = Environment::thread();
        self.owner = Some(tid);
        self.lwp_ptr = Some(thread_state.rump_lwp);
        true
    }

    // SMP ready [1 TODO!]
    fn enter(&mut self) {
        let tid = Environment::tid();
        let yielder: &mut ThreadControlBlock = Environment::thread();

        if self.is_spin {
            self.enter_nowrap();
            return;
        }

        assert!(self.is_kmutex);
        if self.counter.fetch_add(1, Ordering::SeqCst) != 0 {
            // Didn't get the lock:
            let mut rid = 0;
            trace!("try_enter failed deschedule");
            (yielder.upcalls.deschedule)(&mut rid, None);
            self.waitlist.push(tid); // TODO: this needs to be atomic?
            yielder.make_unrunnable(tid);
            (yielder.upcalls.schedule)(&rid, None)
        }
        // Acquired the lock
        self.owner = Some(tid);
        self.lwp_ptr = Some(yielder.rump_lwp);
    }

    fn enter_nowrap(&mut self) {
        loop {
            // Wait till lock is free (counter is 0):
            while self.counter.load(Ordering::Relaxed) != 0 {
                spin_loop_hint();
            }

            // Try to acquire it (set to 1):
            if self.counter.compare_and_swap(0, 1, Ordering::Relaxed) == 0 {
                // continue, we hold the lock now
                break;
            }
            // else: failed to acquire, retry
        }

        let tid = Environment::tid();
        let thread_state = Environment::thread();
        // Acquired the lock
        self.owner = Some(tid);
        self.lwp_ptr = Some(thread_state.rump_lwp);
    }

    /// SMP ready [1 TODO!]
    fn exit(&mut self) {
        let _tid = Environment::tid();
        let yielder: &mut ThreadControlBlock = Environment::thread();

        self.owner = None;
        self.lwp_ptr = None;
        if self.counter.fetch_sub(1, Ordering::SeqCst) != 1 {
            assert!(!self.waitlist.is_empty());
            let next = self.waitlist.pop(); // TODO: this may have to be atomic...
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

#[cfg(test)]
#[test]
fn test_mutex() {
    use alloc::sync::Arc;
    use core::ptr;

    use crate::scheduler::SmpScheduler;
    use crate::stack::DEFAULT_STACK_SIZE_BYTES;
    use crate::tls2::SchedulerControlBlock;

    let _r = env_logger::try_init();

    let s: SmpScheduler = Default::default();
    let mtx = Arc::new(Mutex::new_kmutex());
    let m1: Arc<Mutex> = mtx.clone();
    let m2: Arc<Mutex> = mtx.clone();

    s.spawn(
        DEFAULT_STACK_SIZE_BYTES,
        move |_| {
            info!("before try enter");
            assert!(m2.try_enter());
            info!("after try enter");
            Environment::thread().relinquish();
            m2.exit();
        },
        ptr::null_mut(),
        0,
    );

    s.spawn(
        DEFAULT_STACK_SIZE_BYTES,
        move |_| {
            assert!(!m1.try_enter());
            m1.enter();
            m1.exit();
        },
        ptr::null_mut(),
        0,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    s.run(&scb);
}
