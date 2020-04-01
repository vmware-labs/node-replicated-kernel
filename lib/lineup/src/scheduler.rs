//! The core logic of the scheduler.
//!
//! Has the following properties:
//! * Cooperative scheduling (threads can yield voluntarily)
//! * Round robin scheduling (per-core)
//! * Per core run and wait lists
//! * Thread affinity can be defined upon thread creation (currently no migration)
//! * Waitlist is sorted according to thread wake-up times.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use arr_macro::arr;
use fringe::generator::Generator;
use log::{error, trace};
use rawtime::Instant;

use crate::stack::LineupStack;
use crate::threads::{Runnable, Thread, ThreadId, YieldRequest, YieldResume};
use crate::tls2::{self, SchedulerControlBlock};
use crate::upcalls::Upcalls;
use crate::CoreId;

/// Scheduler per-core state.
///
/// # Lock order
/// `waiting` before `runnable`.
/// In case we need to lock across multiple `SchedulerCoreState`
/// lower `core_id` should be locked first.
struct SchedulerCoreState {
    /// Per-core list of runnable threads.
    ///
    /// Protected by a mutex since anyone could put threads here.
    runnable: spin::Mutex<VecDeque<ThreadId>>,

    /// Per-core list of `waiting` threads.
    ///
    /// Protected by a mutex because anyone could put threads here.
    waiting: spin::Mutex<Vec<(Instant, ThreadId)>>,
}

impl SchedulerCoreState {
    fn new() -> Self {
        SchedulerCoreState {
            runnable: spin::Mutex::new(VecDeque::with_capacity(SmpScheduler::MAX_THREADS)),
            waiting: spin::Mutex::new(Vec::with_capacity(SmpScheduler::MAX_THREADS)),
        }
    }
}

pub struct SmpScheduler<'a> {
    /// All thread generators need to dispatch threads.
    ///
    /// These will be absent if currently in use.
    generators: spin::Mutex<hashbrown::HashMap<ThreadId, Runnable<'a>>>,
    /// All threads in the scheduler.
    threads: spin::Mutex<hashbrown::HashMap<ThreadId, Thread>>,
    /// Scheduler upcalls (as set by the client).
    upcalls: Upcalls,
    /// Per-core scheduler state
    ///
    /// This is slightly different from SchedulerControlBlock
    /// It's per core but only accessed within SmpScheduler
    per_core: [SchedulerCoreState; 64], // MAX_THREADS
    /// Contains a global counter of thread IDs
    tid_counter: AtomicUsize,
}

unsafe impl Send for SmpScheduler<'static> {}
unsafe impl Sync for SmpScheduler<'static> {}

impl<'a> Default for SmpScheduler<'a> {
    fn default() -> Self {
        SmpScheduler::with_upcalls(Default::default())
    }
}

impl<'a> SmpScheduler<'a> {
    pub const MAX_THREADS: usize = 64;

    pub fn with_upcalls(upcalls: Upcalls) -> Self {
        Self {
            generators: spin::Mutex::new(hashbrown::HashMap::with_capacity(
                SmpScheduler::MAX_THREADS,
            )),
            threads: spin::Mutex::new(hashbrown::HashMap::with_capacity(SmpScheduler::MAX_THREADS)),
            upcalls,
            tid_counter: AtomicUsize::new(1),
            per_core: arr![SchedulerCoreState::new(); 64], // MAX_THREADS
        }
    }

    pub fn spawn_with_stack<F>(
        &self,
        stack: LineupStack,
        f: F,
        arg: *mut u8,
        affinity: CoreId,
    ) -> Option<ThreadId>
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let t = self.tid_counter.fetch_add(1, Ordering::Relaxed);
        let tid = ThreadId(t);
        let (handle, generator) =
            unsafe { Thread::new(tid, affinity, stack, f, arg, self.upcalls) };

        self.add_thread(handle, generator).map(|tid| {
            self.mark_runnable(tid, affinity);
            tid
        })
    }

    pub fn spawn<F>(
        &self,
        stack_size: usize,
        f: F,
        arg: *mut u8,
        affinity: CoreId,
    ) -> Option<ThreadId>
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

        if self.threads.lock().len() <= SmpScheduler::MAX_THREADS {
            self.threads.lock().insert(tid, handle);
            self.generators.lock().insert(tid, generator);
            Some(tid)
        } else {
            error!("too many threads");
            return None;
        }
    }

    /// Marks a thread as sunnable by inserting it into
    /// `runnable`.
    fn mark_runnable(&self, tid: ThreadId, affinity: CoreId) {
        self.per_core[affinity].runnable.lock().push_back(tid);
    }

    /// Make a thread no longer runnable.
    ///
    /// Anything that's not in runnable is unrunnable.
    /// This is O(n) but it happens rarely(?); only
    /// call it if tid is different from current thread.
    fn mark_unrunnable(&self, tid: ThreadId, affinity: CoreId) {
        let mut runnable = self.per_core[affinity].runnable.lock();
        runnable.retain(|&ltid| ltid != tid);
    }

    /// Insert thread in a sorted waitlist
    fn waitlist_insert(&self, tid: ThreadId, affinity: CoreId, until: Instant) {
        let mut waiting = self.per_core[affinity].waiting.lock();
        let to_insert = (until, tid);
        match waiting.binary_search_by(|probe| probe.cmp(&to_insert).reverse()) {
            Err(pos) => waiting.insert(pos, to_insert),
            Ok(_pos) => panic!("Thread already in waitlist?"),
        }
        trace!("Waitlist is {:?}", waiting);
    }

    /// Handles a yield request of the thread given by `tid`.
    ///
    /// Updates run and waitlists accordingly.
    fn handle_yield_request(&self, tid: ThreadId, result: Option<YieldRequest>) -> YieldResume {
        let affinity = self.threads.lock().get(&tid).unwrap().affinity;
        match result {
            None => {
                trace!("Thread {} has terminated.", tid);
                self.mark_unrunnable(tid, affinity);
                self.threads
                    .lock()
                    .remove(&tid)
                    .expect("Can't remove thread?");
                YieldResume::DoNotResume
            }
            Some(YieldRequest::None) => {
                trace!(
                    "Thread {} has voluntarily yielded its time (YieldRequest::None).",
                    tid
                );
                // Put us back at end of the queue:
                self.mark_runnable(tid, affinity);
                YieldResume::Interrupted
            }
            Some(YieldRequest::Runnable(rtid)) => {
                trace!("YieldRequest::Runnable {:?} {}", rtid, affinity);
                let rtid_affinity = self
                    .threads
                    .lock()
                    .get(&rtid)
                    .expect("Can't find thread")
                    .affinity;
                self.mark_runnable(rtid, rtid_affinity);
                YieldResume::Completed
            }
            Some(YieldRequest::Unrunnable(rtid)) => {
                trace!("YieldRequest::Unrunnable {:?}", rtid);
                let rtid_affinity = self
                    .threads
                    .lock()
                    .get(&rtid)
                    .expect("Can't find thread")
                    .affinity;
                if rtid == tid {
                    // No-op (already popped tid from running) but force context switch:
                    YieldResume::Interrupted
                } else {
                    // Slow path
                    self.mark_unrunnable(rtid, rtid_affinity);
                    // Do not need to context switch, continue running
                    YieldResume::Completed
                }
            }
            Some(YieldRequest::RunnableList(rtids)) => {
                trace!("YieldRequest::RunnableList {:?}", rtids);
                for rtid in rtids.iter() {
                    let rtid_affinity = self
                        .threads
                        .lock()
                        .get(&rtid)
                        .expect("Can't find thread")
                        .affinity;
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
                self.waitlist_insert(tid, affinity, until);
                // Already popped from running, force context switch
                YieldResume::Interrupted
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
                        affinity,
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
                        affinity,
                    )
                    .expect("Can't spawn the thread");
                YieldResume::Spawned(tid)
            }
        }
    }

    /// Finds threads with expired timeouts and re-inserts them from `waiting` into `runnable`
    ///
    /// Acquires lock on `waiting` and `runnable`.
    /// TODO(style): Maybe should avoid taking both locks here to avoid deadlock.
    /// TODO(efficiency): Should probably avoid taking `runnable` lock multiple times.
    fn check_wakeups(&self, affinity: CoreId) {
        let mut waiting = self.per_core[affinity].waiting.lock();
        while !waiting.is_empty() && waiting.last().unwrap().0 <= Instant::now() {
            if let Some((_wakeup, tid)) = waiting.pop() {
                self.mark_runnable(tid, affinity);
            }
        }
    }

    /// Dispatches one thread, runs it until it yields again.
    ///
    /// Also checks if any waiting threads need to be woken up.
    /// Returns immediately if no thread is runnable.
    ///
    /// TODO(api-design): Ideally we would use the TypeSystem to prevent
    /// SchedulerControlBlock being used multiple times
    /// `run(scb: SchedCtlBlock) -> SchedCtlBlock`
    /// But once it's there it needs to stick in the fs reg. so we can
    /// access it on incoming IRQs.
    /// Maybe run() should just never return?
    pub fn run(&self, scb: &SchedulerControlBlock) {
        let core_id = scb.core_id;

        unsafe {
            // Set the schedler control block -- may have already been installed
            // But in some weird scenario someone might end up with two schedulers
            // on the same core...
            tls2::arch::set_scb(scb as *const SchedulerControlBlock);
        }

        // Run until `runnable` is empty.
        loop {
            self.check_wakeups(core_id);

            // The next thread ID we want to run
            let next_tid = self.per_core[core_id].runnable.lock().pop_front();
            match next_tid {
                Some(tid) => {
                    let mut generator = self
                        .generators
                        .lock()
                        .remove(&tid)
                        .expect("Can't find thread state?");

                    let mut resume_action: YieldResume = {
                        let thread_map = self.threads.lock();
                        let thread = thread_map.get(&tid).expect("Can't find thread state?");
                        trace!("Thread = {:?}", thread);

                        // Only overwrite the thread control block in case this is
                        // not null (i.e., not a new thread). A new thread will
                        // allocate the TCB itself
                        if !thread.state.is_null() {
                            unsafe {
                                tls2::arch::set_tcb(thread.state);
                            }
                        }

                        thread.return_with.unwrap_or(YieldResume::Completed)
                    };

                    // Run the thread until `handle_yield_request` decides on a context-switch
                    // or the thread is done:
                    loop {
                        trace!("generator.resume = {:?}", resume_action);
                        let yielded_with = generator.resume(resume_action);
                        trace!("yielded_with = {:?}", yielded_with);
                        resume_action = self.handle_yield_request(tid, yielded_with);
                        trace!("resume_action = {:?}", resume_action);
                        if resume_action == YieldResume::Interrupted {
                            // If we're not done we need to put the generator back:
                            self.generators.lock().insert(tid, generator);

                            // And preserve the TLS value in the Thread struct:
                            let mut thread_map = self.threads.lock();
                            let thread =
                                thread_map.get_mut(&tid).expect("Can't find thread state?");
                            // Also preserve the TLS
                            if thread.state.is_null() {
                                unsafe {
                                    thread.state = tls2::arch::get_tcb();
                                }
                            }
                            assert!(!thread.state.is_null());
                            break;
                        }
                        if resume_action == YieldResume::DoNotResume {
                            // We're done with this thread for good
                            break;
                        }
                    }
                    // else: We can drop the generator

                    // Unset the TCB (TODO: silly optimization avoid unsetting if next running is current tid...)
                    unsafe {
                        tls2::arch::set_tcb(ptr::null_mut());
                    }
                }
                None => {
                    // Nothing to dispatch
                    // Maybe return the next event that will happen on that scheduler?
                    break;
                }
            }
        }

        // TODO(bad-design): see comment above
        // We can't really unset this since when we return, an IRQ may still come
        // tls2::arch::set_scb(&self.scb as *const SchedulerControlBlock);
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::time::Duration;
    use std::thread;

    use crossbeam_queue::ArrayQueue;
    use log::info;

    use super::*;
    use crate::stack::DEFAULT_STACK_SIZE_BYTES;
    use crate::threads::*;
    use crate::tls2::Environment;
    use crate::*;

    /// Test that the runnable list of a core can be accessed in parallel
    /// This is done by spawning two pthreads that dispatch from the core 0
    /// lineup waitlist.
    #[test]
    fn runnable_is_scheduler_aware() {
        // Create a scheduler and reference to it
        let s: Arc<SmpScheduler> = Arc::new(Default::default());
        let s1 = s.clone();
        let s2 = s.clone();

        // And a queue where we can concurrently store results
        let seen_threads1: Arc<ArrayQueue<std::thread::ThreadId>> = Arc::new(ArrayQueue::new(2));
        let seen_threads2 = seen_threads1.clone();
        let seen_threads = seen_threads1.clone();

        // Spawn two lineup threads on "core 0", each thread pushes its underlying posix thread id
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                let _r = seen_threads1.push(thread::current().id());
            },
            ptr::null_mut(),
            0,
        );
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                let _r = seen_threads2.push(thread::current().id());
            },
            ptr::null_mut(),
            1,
        );

        // Spawn two pthreads each will dispatch lineup threads from "core 0"
        // to test concurrency
        let t1 = thread::spawn(move || {
            let scb1: SchedulerControlBlock = SchedulerControlBlock::new(0);
            for _i in 1..10 {
                s1.run(&scb1);
            }
        });

        let t2 = thread::spawn(move || {
            let scb2: SchedulerControlBlock = SchedulerControlBlock::new(1);
            for _i in 1..10 {
                s2.run(&scb2);
            }
        });

        // Wait for pthreads to finish
        let _r = t1.join();
        let _r = t2.join();

        // Make sure that the threads have execute on different pthreads
        // even though we ran both with "core 0" affinity
        assert!(seen_threads.len() == 2);
        let ptid1 = seen_threads.pop().unwrap();
        let ptid2 = seen_threads.pop().unwrap();
        assert_ne!(
            ptid1, ptid2,
            "Lineup Threads didn't run on different pthreads?"
        );
    }

    /// Checks that the scheduler can run in parallel.
    ///
    /// Running two long computations on two cores shouldn't take
    /// longer than running just one on one core.
    #[test]
    fn scheduler_is_parallel() {
        let _r = env_logger::try_init();

        // Create a scheduler and reference to it
        let s: Arc<SmpScheduler> = Arc::new(Default::default());
        let s1 = s.clone();
        let s2 = s.clone();

        // A silly is_prime checker
        fn is_prime(n: u64) -> bool {
            for a in 2..n {
                if n % a == 0 {
                    return false;
                }
            }
            true
        }

        // Find out how long it takes on one core
        let the_prime: u64 = 10000789;
        let ref_start = Instant::now();
        let r = is_prime(the_prime);
        let ref_end = Instant::now();

        // Spawn two lineup threads (with two underlying pthreads), each thread computes is_prime
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                is_prime(the_prime);
            },
            ptr::null_mut(),
            0,
        );
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                is_prime(the_prime);
            },
            ptr::null_mut(),
            1,
        );

        // Spawn two pthreads each will dispatch lineup threads from "core 0"
        // to test concurrency
        let pstart = Instant::now();
        let t1 = thread::spawn(move || {
            let scb1: SchedulerControlBlock = SchedulerControlBlock::new(0);
            s1.run(&scb1);
        });

        let t2 = thread::spawn(move || {
            let scb2: SchedulerControlBlock = SchedulerControlBlock::new(1);
            s2.run(&scb2);
        });
        let _r = t1.join();
        let _r = t2.join();
        let pend = Instant::now();

        let ref_duration = ref_end - ref_start;
        let exp_duration = pend - pstart;

        trace!("Baseline {} {:?}", r, ref_end - ref_start);
        trace!("Two threads {} {:?}", r, pend - pstart);
        assert!(
            ref_end - ref_start > Duration::from_millis(100),
            "Baseline should take a sufficient amount of time"
        );
        // Running computation twice on two threads shouldn't take longer than running it once
        assert!(
            exp_duration >= ref_duration - Duration::from_millis(50),
            "Lineup was too fast?"
        );
        assert!(
            exp_duration <= ref_duration + Duration::from_millis(50),
            "Lineup was too slow?"
        );
    }

    /// Test that waitlist inserts are inserted with correct order.
    #[test]
    fn waitlist_inserts_are_sorted() {
        let t0 = ThreadId(1);
        let t0n = Instant::now();

        let t1 = ThreadId(2);
        let t1n = Instant::now();

        let t2 = ThreadId(3);
        let t2n = Instant::now();

        assert!(t0n < t1n);
        assert!(t1n < t2n);

        // Make two schedulers
        let s1: Arc<SmpScheduler> = Default::default();
        let s2: Arc<SmpScheduler> = Default::default();

        // Insert in both different order:
        s1.waitlist_insert(t0, 0, t0n);
        s1.waitlist_insert(t1, 0, t1n);
        s1.waitlist_insert(t2, 0, t2n);

        s2.waitlist_insert(t2, 0, t2n);
        s2.waitlist_insert(t1, 0, t1n);
        s2.waitlist_insert(t0, 0, t0n);

        // Order should not depend on insertion order
        debug_assert_eq!(
            *s1.per_core[0].waiting.lock(),
            *s2.per_core[0].waiting.lock(),
            "List order depends on insert order?"
        );

        let waitlist = s1.per_core[0].waiting.lock();
        // Event with shortest wakeup time is last:
        debug_assert!(waitlist[0].1 == ThreadId(3));
        debug_assert!(waitlist[1].1 == ThreadId(2));
        debug_assert!(waitlist[2].1 == ThreadId(1));
    }

    /// Test that sleeping events wake up in the correct order
    /// and sleep as long as we expect them to.
    #[test]
    fn waitlist_wakeup() {
        let _r = env_logger::try_init();
        use crossbeam_queue::ArrayQueue;

        let s: Arc<SmpScheduler> = Default::default();

        let timelog: Arc<ArrayQueue<(ThreadId, Instant)>> = Arc::new(ArrayQueue::new(4));
        let timelog1 = timelog.clone();
        let timelog2 = timelog.clone();

        let t1_waittime = Duration::from_millis(50);
        let t2_waittime = Duration::from_millis(70);

        // Spawn two threads that sleep for the given wait times
        // log their sleep and wakeup time
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                let _r = timelog1.push((Environment::tid(), Instant::now()));
                Environment::thread().sleep(t1_waittime);
                let _r = timelog1.push((Environment::tid(), Instant::now()));
            },
            ptr::null_mut(),
            0,
        );

        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                let _r = timelog2.push((Environment::tid(), Instant::now()));
                Environment::thread().sleep(t2_waittime);
                let _r = timelog2.push((Environment::tid(), Instant::now()));
            },
            ptr::null_mut(),
            0,
        );

        // Run the scheduler for 100 ms
        let start = Instant::now();
        let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
        while start.elapsed() < Duration::from_millis(100) {
            s.run(&scb);
        }
        assert_eq!(timelog.len(), 4, "All threads woke up again.");

        // Determine beginning of sleep and sleep duration for t1, t2
        let mut t1_start: Option<Instant> = None;
        let mut t1_observed: Option<Duration> = None;

        let mut t2_start: Option<Instant> = None;
        let mut t2_observed: Option<Duration> = None;

        for _i in 0..4 {
            let (tid, instant) = timelog.pop().unwrap();
            info!("got tid {:?} instant {:?}", tid, instant);
            if tid == ThreadId(1) {
                t1_start.map_or_else(
                    || t1_start = Some(instant),
                    |start| {
                        t1_observed = Some(instant - start);
                    },
                );
            }

            if tid == ThreadId(2) {
                t2_start.map_or_else(
                    || t2_start = Some(instant),
                    |start| {
                        t2_observed = Some(instant - start);
                    },
                );
            }
        }

        // Make sure that the observed/logged sleep times are
        // within some bound of the expected sleep time:
        let t1_duration = t1_observed.expect("Didn't find duration");
        assert!(t1_duration >= t1_waittime);
        assert!(t1_duration <= t1_waittime + Duration::from_millis(1));

        let t2_duration = t2_observed.expect("Didn't find duration");
        assert!(t2_duration >= t2_waittime);
        assert!(t2_duration <= t2_waittime + Duration::from_millis(1));
    }
}
