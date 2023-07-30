// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::cell::Cell;
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use kpi::process::MAX_CORES;

use crate::threads::ThreadId;
use crate::tls2::{Environment, ThreadControlBlock};

use crossbeam_queue::ArrayQueue;
use crossbeam_utils::CachePadded;
use log::*;

#[derive(Debug)]
pub struct Mutex {
    inner: MutexInner,
}

impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
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
            inner: MutexInner {
                owner: Cell::new(None),
                lwp_ptr: Cell::new(ptr::null()),
                is_kmutex,
                is_spin,
                waitlist: ArrayQueue::new(MAX_CORES),
                counter: CachePadded::new(AtomicUsize::new(0)),
            },
        }
    }

    pub fn is_kmutex(&self) -> bool {
        self.inner.is_kmutex
    }

    pub fn is_spin(&self) -> bool {
        self.inner.is_spin
    }

    pub fn try_enter(&self) -> bool {
        self.inner.try_enter()
    }

    pub fn enter(&self) {
        self.inner.enter();
    }

    pub fn enter_nowrap(&self) {
        self.inner.enter_nowrap();
    }

    pub fn exit(&self) {
        self.inner.exit();
    }

    pub fn owner(&self) -> *const u64 {
        self.inner.owner()
    }
}

#[derive(Debug)]
struct MutexInner {
    is_kmutex: bool,
    is_spin: bool,

    owner: Cell<Option<ThreadId>>,
    lwp_ptr: Cell<*const u64>,

    waitlist: ArrayQueue<ThreadId>,

    /// Counting how many are interested currently in the mutex
    /// and ensures mutual exclusion of resource:
    /// A value of 0: The mutex is not locked.
    /// A value of 1: The mutex is locked, no waiters.
    /// A value of >1: The mutex is locked and has (or will have) waiters in waitlist.
    counter: CachePadded<AtomicUsize>,
}

impl MutexInner {
    fn try_enter(&self) -> bool {
        let tid = Environment::tid();
        assert!(
            self.owner.get() != Some(tid),
            "Locking mutex against itself."
        );

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
            match self
                .counter
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,     // we hold the lock now
                Err(_) => continue, // failed to acquire, retry
            }
        }

        let thread_state = Environment::thread();
        self.owner.replace(Some(tid));
        self.lwp_ptr
            .replace(thread_state.rump_lwp.load(Ordering::SeqCst));
        true
    }

    fn enter(&self) {
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
            // What if another core makes this runnable/runs it before we're made unrunnable?
            // (i.e., counter+1, waitlist.push, exit, make unrunnable)
            // A problem is if we would steal the thread and execute it on another core (we don't currently)
            // It would likely error because we wouldn't find the generator in the hashmap (it's taken out of the
            // map whenever we run a thread)
            // A better idea is probably to provide a callback to the yielder which then pushes
            // us in the waitlist after we've restored the generator (this would ensure we only update waitlist
            // after the generator has switched back to the scheduler context and is in a consistent state)
            assert!(self.waitlist.push(tid).is_ok());

            // This is fine as long as tid == self, in the scheduler we will just pop the front of runnable
            // instead of searching the whole list and discarding everhting that is tid:
            // if that were the case we would have a race when `exit` inserts us again at the end of runnable
            // before we call unrunnable here (and then removing all tids...)
            // Right now since we don't migrate:
            // push -> exit (put `tid` on back of runnable) -> unrunnable (pop `tid` in front or runnable)
            // is a fine ordering
            yielder.make_unrunnable(tid);
            (yielder.upcalls.schedule)(&rid, None)
        } else {
            // Acquired immediately
        }

        // Acquired the lock
        self.owner.replace(Some(tid));
        self.lwp_ptr
            .replace(yielder.rump_lwp.load(Ordering::SeqCst));
    }

    fn enter_nowrap(&self) {
        let yielder: &mut ThreadControlBlock = Environment::thread();

        loop {
            // Wait till lock is free (counter is 0):
            #[cfg(feature = "latency")]
            let start = rawtime::Instant::now();

            while self.counter.load(Ordering::SeqCst) != 0 {
                // relinquish() was added after finding a bug where no progress was able to be made.
                // in this case, there were two threads scheduled on the same core who wanted this
                // mutex, and the thread who woke up first went into enter_nowrap (this function),
                // entered the spin loop, and did not give up the core to the other thread who could
                // have made progress. Relinquish gives a different thread a chance to get the mutex.
                yielder.relinquish();

                spin_loop();
            }

            #[cfg(feature = "latency")]
            if start.elapsed() > core::time::Duration::from_nanos(200) {
                warn!("spun for {:?}", start.elapsed());
            }

            // Try to acquire it (set to 1):
            match self
                .counter
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,     // we hold the lock now
                Err(_) => continue, // failed to acquire, retry
            }
        }

        let tid = Environment::tid();
        let thread_state = Environment::thread();
        // Acquired the lock
        self.owner.replace(Some(tid));
        self.lwp_ptr
            .replace(thread_state.rump_lwp.load(Ordering::SeqCst));
    }

    fn exit(&self) {
        let yielder: &mut ThreadControlBlock = Environment::thread();

        let _prev = self.owner.replace(None);
        let _prev_ptr = self.lwp_ptr.replace(ptr::null());

        let v = self.counter.fetch_sub(1, Ordering::SeqCst);
        if v < 1 {
            let tid = Environment::tid();
            panic!("{:?} Called exit on already released mtx={:p}", tid, self);
        }
        // if v == 1 { "No one there to wake up" }
        if v > 1 {
            // Need to resolve a race where we call `exit`
            // but another thread that called enter has incremented
            // counter but not put itself in the waitlist yet
            loop {
                #[cfg(feature = "latency")]
                let start = rawtime::Instant::now();
                while self.waitlist.is_empty() {
                    spin_loop();
                }
                #[cfg(feature = "latency")]
                if start.elapsed() > core::time::Duration::from_nanos(200) {
                    warn!("waitlist waited for {:?}", start.elapsed());
                }

                match self.waitlist.pop() {
                    Some(next) => {
                        yielder.make_runnable(next);
                        break;
                    }
                    None => {
                        spin_loop();
                        continue;
                    }
                }
            }
        }
    }

    fn owner(&self) -> *const u64 {
        self.lwp_ptr.get()
    }
}

impl Drop for MutexInner {
    fn drop(&mut self) {
        assert!(self.waitlist.is_empty());
        assert!(self.owner.get().is_none());
        assert!(self.lwp_ptr.get().is_null());
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
            trace!("before try enter");
            assert!(m2.try_enter());
            trace!("after try enter");
            Environment::thread().relinquish();
            m2.exit();
        },
        ptr::null_mut(),
        0,
        None,
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
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    s.run(&scb);
}

#[cfg(test)]
#[test]
fn test_mutex_smp() {
    use alloc::sync::Arc;
    use core::cell::UnsafeCell;
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

    // Spawn 4 threads on three cores
    let n = 4;
    let c = 3;

    let s: Arc<SmpScheduler> = Default::default();
    // Make a spinning mutex
    let spin_increment = 1000;
    let mtx = Arc::new(Mutex::new_spin());
    // A counter to test the mutex
    let spin_counter: Arc<UnsafeSyncCell<usize>> = Arc::new(UnsafeSyncCell::new(0));
    // And a 'kernel' mutex
    let kmtx_increment = 500;
    let kmtx = Arc::new(Mutex::new_kmutex());
    // A counter to test the kmutex
    let kcounter: Arc<UnsafeSyncCell<usize>> = Arc::new(UnsafeSyncCell::new(0));

    // Threads increment unprotected counter with mutex n*X times
    for idx in 0..n {
        let mtx: Arc<Mutex> = mtx.clone();
        let spin_counter = spin_counter.clone();

        let kmtx: Arc<Mutex> = kmtx.clone();
        let kcounter = kcounter.clone();

        log::info!("spawn in c %idx = {}", idx % c);
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                for _i in 0..spin_increment {
                    mtx.enter();

                    unsafe {
                        *spin_counter.inner.get() += 1;
                    }
                    mtx.exit();
                }

                for i in 0..kmtx_increment {
                    kmtx.enter();
                    unsafe {
                        *kcounter.inner.get() += 1;
                    }
                    if i % 45 == 0 {
                        Environment::thread().relinquish();
                    }
                    kmtx.exit();
                }
            },
            ptr::null_mut(),
            idx % c,
            None,
        );
    }

    let mut cores = Vec::with_capacity(c);
    for idx in 0..c {
        let s1 = s.clone();
        cores.push(thread::spawn(move || {
            let scb: SchedulerControlBlock = SchedulerControlBlock::new(idx);
            let start = Instant::now();
            while start.elapsed().as_secs() < 2 {
                s1.run(&scb);
            }
        }));
    }

    for c in cores {
        let _r = c.join().unwrap();
    }

    unsafe {
        assert_eq!(*spin_counter.inner.get(), n * spin_increment);
        assert_eq!(*kcounter.inner.get(), n * kmtx_increment);
    }
}
