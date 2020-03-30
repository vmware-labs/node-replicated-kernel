use arr_macro::arr;
use core::fmt;
use rawtime::Instant;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
mod ds {
    pub use hashbrown::HashMap;
    pub use std::sync::Arc;
    pub use std::vec::Vec;
}

#[cfg(not(test))]
mod ds {
    pub use alloc::boxed::Box;
    pub use alloc::sync::Arc;
    pub use alloc::vec::Vec;
    pub use hashbrown::HashMap;
}

use core::hash::{Hash, Hasher};
use core::ops::Add;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;
use log::*;

use super::mutex;
use super::stack::LineupStack;
use super::tls;
use super::*;

use fringe::generator::{Generator, Yielder};
use fringe::Stack;

type Runnable<'a> = Generator<'a, YieldResume, YieldRequest, LineupStack>;

struct SchedulerCoreState {
    /// Thread local storage
    tls: tls::ThreadLocalStorage<'static>,

    /// Core identifier of this scheduler state
    /// (SmpScheduler.per_core[core_id] should point to this struct)
    core_id: usize,
    /// Per-core list of runnable threads.
    ///
    /// Protected by a mutex since anyone could put threads here.
    runnable: spin::Mutex<ds::Vec<ThreadId>>,

    /// Per-core list of `waiting` threads.
    ///
    /// Protected by a mutex because anyone could put threads here.
    waiting: spin::Mutex<ds::Vec<(Instant, ThreadId)>>,

    /// IRQ pending notification (set by upcall handler)
    ///
    /// Atomic because we can't prevent the scheduler holding the spin lock
    /// to runnable if we get an IRQ.
    signal_irq: AtomicBool,

    /// To communicate a list of threads to the scheduler
    pub(crate) make_runnable: ds::Vec<ThreadId>,
}

impl SchedulerCoreState {
    fn new() -> Self {
        SchedulerCoreState {
            tls: tls::ThreadLocalStorage::new(),
            core_id: 0,
            signal_irq: AtomicBool::new(false),
            runnable: spin::Mutex::new(ds::Vec::with_capacity(SmpScheduler::MAX_THREADS)),
            waiting: spin::Mutex::new(ds::Vec::with_capacity(SmpScheduler::MAX_THREADS)),
            make_runnable: ds::Vec::with_capacity(SmpScheduler::MAX_THREADS),
        }
    }
}

pub struct SmpScheduler<'a> {
    /// All thread generators need to dispatch threads.
    ///
    /// These will be absent if currently in use.
    generators: spin::Mutex<ds::HashMap<ThreadId, Runnable<'a>>>,
    /// All threads in the scheduler.
    threads: spin::Mutex<ds::HashMap<ThreadId, Thread>>,
    /// Scheduler upcalls (as set by the client).
    upcalls: Upcalls,
    pub rump_upcalls: *const u64,
    pub rump_version: i64,
    /// Per-core scheduler state
    per_core: [SchedulerCoreState; 64], // MAX_THREADS
    tid_counter: AtomicUsize,
}

unsafe impl Send for SmpScheduler<'static> {}
unsafe impl Sync for SmpScheduler<'static> {}

impl<'a> SmpScheduler<'a> {
    pub const MAX_THREADS: usize = 64;

    pub fn new(upcalls: Upcalls) -> Self {
        Self {
            generators: spin::Mutex::new(ds::HashMap::with_capacity(SmpScheduler::MAX_THREADS)),
            threads: spin::Mutex::new(ds::HashMap::with_capacity(SmpScheduler::MAX_THREADS)),
            upcalls,
            rump_upcalls: ptr::null(),
            rump_version: 0,
            tid_counter: AtomicUsize::new(1),
            per_core: arr![SchedulerCoreState::new(); 64], // MAX_THREADS
        }
    }

    pub fn spawn_with_stack<F>(&self, stack: LineupStack, f: F, arg: *mut u8, affinity: CoreId) -> Option<ThreadId>
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let t = self.tid_counter.fetch_add(1, Ordering::Relaxed);
        let tid = ThreadId(t);
        let (handle, generator) = unsafe { Thread::new(tid, affinity, stack, f, arg, self.upcalls) };

        self.add_thread(handle, generator).map(|tid| {
            self.mark_runnable(tid, affinity);
            tid
        })
    }

    pub fn spawn<F>(&self, stack_size: usize, f: F, arg: *mut u8, affinity: CoreId) -> Option<ThreadId>
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let stack = LineupStack::from_size(stack_size);
        self.spawn_with_stack(stack, f, arg, affinity)
    }

    fn add_thread(
        &self,
        handle: Thread,
        generator: Generator<'a, YieldResume, YieldRequest, LineupStack>,
    ) -> Option<ThreadId> {
        let tid = handle.id.clone();
        assert!(
            !self.threads.lock().contains_key(&tid),
            "Thread {} already exists?",
            tid
        );

        if self.threads.lock().len() <= Scheduler::MAX_THREADS {
            self.threads.lock().insert(tid, handle);
            self.generators.lock().insert(tid, generator);
            Some(tid)
        } else {
            error!("too many threads");
            return None;
        }
    }

    fn mark_runnable(&self, tid: ThreadId, affinity: CoreId) {
        self.per_core[affinity].runnable.lock().push(tid);
    }

    fn mark_unrunnable(&self, tid: ThreadId, affinity: CoreId) {
        self.per_core[affinity].runnable.lock().remove_item(&tid);
    }

    /// Insert thread in a sorted waitlist
    fn waitlist_insert(&self, tid: ThreadId, affinity: CoreId, until: Instant) {
        let mut waiting = self.per_core[affinity].waiting.lock();
        let to_insert = (until, tid);
        match waiting.binary_search(&to_insert) {
            Err(pos) => waiting.insert(pos, to_insert),
            Ok(pos) => panic!("Thread already in waitlist?"),
        }
        trace!("Waitlist is {:?}", waiting);
    }

    fn handle_yield_request(&self, tid: ThreadId, generator: Runnable<'a>,  result: Option<YieldRequest>) -> YieldResume {
        let affinity = self.threads.lock().get(&tid).unwrap().affinity;

        match result {
            None => {
                trace!("Thread {} has terminated.", tid);
                self.mark_unrunnable(tid, affinity);
                unsafe {
                    tls::set_thread_state(ptr::null_mut());
                }
                self.threads.lock().remove(&tid).expect("Can't remove thread?");
                // for join calls do wakeups here...
                drop(generator);
                YieldResume::DoNotResume
            }
            Some(YieldRequest::None) => {
                trace!("Thread {} has YieldRequest::None.", tid);
                // XXX: why is this here: self.mark_unrunnable(tid, affinity);
                self.mark_runnable(tid, affinity);
                YieldResume::Completed
            }
            Some(YieldRequest::Runnable(rtid)) => {
                trace!("YieldRequest::Runnable {:?} {}", rtid, affinity);
                self.mark_runnable(rtid, affinity);
                YieldResume::Completed
            }
            Some(YieldRequest::Unrunnable(rtid)) => {
                trace!("YieldRequest::Unrunnable {:?}", rtid);
                let rtid_affinity = self.threads.lock().get(&rtid).expect("Can't find thread").affinity;
                self.mark_unrunnable(rtid, rtid_affinity);
                YieldResume::Completed
            }
            Some(YieldRequest::RunnableList(rtids)) => {
                trace!("YieldRequest::RunnableList {:?}", rtids);
                for rtid in rtids.iter() {
                    let rtid_affinity = self.threads.lock().get(&rtid).expect("Can't find thread").affinity;
                    self.mark_runnable(*rtid, rtid_affinity);
                }
                YieldResume::Completed
            }
            Some(YieldRequest::Timeout(until)) => {
                trace!(
                    "The thread #{:?} has suspended itself until {:?}.",
                    tid,
                    until.duration_since(Instant::now()),
                );
                self.mark_unrunnable(tid, affinity);
                self.waitlist_insert(tid, affinity, until);
                YieldResume::Completed
            }
            Some(YieldRequest::Spawn(function, arg, affinity)) => {
                trace!("self.spawn {:?} {:p}", function, arg);
                let tid = self
                    .spawn(
                        64 * 4096,
                        move |arg| unsafe {
                            (function.unwrap())(arg);
                        },
                        arg,
                        affinity
                    )
                    .expect("Can't spawn the thread");
                YieldResume::Spawned(tid)
            }
            Some(YieldRequest::SpawnWithStack(stack, function, arg, affinity)) => {
                trace!("self.spawn {:?} {:p}", function, arg);
                let tid = self
                    .spawn_with_stack(
                        stack,
                        move |arg| unsafe {
                            (function.unwrap())(arg);
                        },
                        arg,
                        affinity
                    )
                    .expect("Can't spawn the thread");
                YieldResume::Spawned(tid)
            }
        }
    }

    pub fn run(&self) {
        let core_id = 0;

        // The next thread ID we want to run
        let tid = self.per_core[core_id].runnable.lock().pop();

        if tid.is_some() {
            let tid = tid.unwrap();
            let mut generator = self
                .generators
                .lock()
                .remove(&tid)
                .expect("Can't find thread state?");

            let action: YieldResume = {
                let thread_map = self.threads.lock();
                let thread = thread_map.get(&tid)
                    .expect("Can't find thread state?");
                trace!("thread = {:?}", thread);
                thread.return_with.unwrap_or(YieldResume::Completed)
            };

            info!("Dispatching {} with {:?}", tid, action);
            let yielded_with = generator.resume(action);
            let resume_action = self.handle_yield_request(tid, generator, yielded_with);
        }
        else {
            trace!("Nothing to run");
        }

    }
}

#[derive(Debug, Clone)]
pub struct ThreadState<'a> {
    yielder: &'a Yielder<YieldResume, YieldRequest>,
    tid: ThreadId,
    pub upcalls: Upcalls,
    pub rump_lwp: *const u64,
    pub rumprun_lwp: *const u64,
}

impl<'a> ThreadState<'a> {
    fn yielder(&self) -> &'a Yielder<YieldResume, YieldRequest> {
        self.yielder
    }

    pub fn set_lwp(&mut self, lwp_ptr: *const u64) {
        self.rump_lwp = lwp_ptr;
    }

    pub fn spawn_with_stack(
        &self,
        s: LineupStack,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
        affinity: CoreId
    ) -> Option<ThreadId> {
        let request = YieldRequest::SpawnWithStack(s, f, arg, affinity);
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn spawn(
        &self,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
        affinity: CoreId
    ) -> Option<ThreadId> {
        let request = YieldRequest::Spawn(f, arg, affinity);
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn sleep(&self, d: Duration) {
        let request = YieldRequest::Timeout(Instant::now().add(d));
        self.yielder().suspend(request);
    }

    pub fn block(&self) {
        let request = YieldRequest::Unrunnable(tls::Environment::tid());
        self.yielder().suspend(request);
    }

    pub fn make_runnable(&self, tid: ThreadId) {
        let request = YieldRequest::Runnable(tid);
        self.yielder().suspend(request);
    }

    fn make_all_runnable(&self, tids: ds::Vec<ThreadId>) {
        let request = YieldRequest::RunnableList(tids);
        self.yielder().suspend(request);
    }

    fn make_unrunnable(&self, tid: ThreadId) {
        let request = YieldRequest::Unrunnable(tid);
        self.yielder().suspend(request);
    }

    fn suspend(&self, request: YieldRequest) {
        self.yielder().suspend(request);
    }

    pub fn relinquish(&self) {
        self.suspend(YieldRequest::None);
    }
}

#[test]
fn smp_sched() {
    use crate::ds;
    use crate::mutex::Mutex;
    use std::thread;

    let mut s = ds::Arc::new(SmpScheduler::new(DEFAULT_UPCALLS));
    let mtx = ds::Arc::new(Mutex::new(false, true));
    let m1: ds::Arc<Mutex> = mtx.clone();
    let m2: ds::Arc<Mutex> = mtx.clone();
    info!("main {:?}", thread::current().id());

    s.spawn(
        32 * 4096,
        move |_| {
            info!("s2 {:?}", thread::current().id());
        },
        ptr::null_mut(),
        0
    );

    s.spawn(
        32 * 4096,
        move |_| {
            info!("s1 {:?}", thread::current().id());
        },
        ptr::null_mut(),
        0
    );

    let s1 = s.clone();
    let s2 = s.clone();

    let t1 = thread::spawn(move || {
        for i in 1..10 {
            s1.run();
        }
    });

    let t2 = thread::spawn(move || {
        for i in 1..10 {
            s2.run();
        }
    });

    let _r = t1.join();
    let _r = t2.join();
}
