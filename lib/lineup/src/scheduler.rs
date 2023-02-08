// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
use kpi::process::MAX_CORES;
use log::{error, trace};
use rawtime::Instant;

use crate::stack::LineupStack;
use crate::threads::{Runnable, Thread, ThreadId, YieldRequest, YieldResume};
use crate::tls2::{self, SchedulerControlBlock, ThreadControlBlock};
use crate::upcalls::Upcalls;
use crate::{CoreId, IrqVector};

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
    per_core: [SchedulerCoreState; MAX_CORES],
    /// Contains a global counter of thread IDs
    tid_counter: AtomicUsize,
    /// TODO(rackscale): may need to make IrqVector unique w/ machine id?
    /// Maps interrupt vectors to ThreadId
    irqvec_to_tid: spin::Mutex<hashbrown::HashMap<IrqVector, ThreadId>>,
}

unsafe impl Send for SmpScheduler<'static> {}
unsafe impl Sync for SmpScheduler<'static> {}

impl<'a> Default for SmpScheduler<'a> {
    fn default() -> Self {
        SmpScheduler::with_upcalls(Default::default())
    }
}

impl<'a> SmpScheduler<'a> {
    pub const MAX_THREADS: usize = 2048;

    pub fn with_upcalls(upcalls: Upcalls) -> Self {
        Self {
            generators: spin::Mutex::new(hashbrown::HashMap::with_capacity(
                SmpScheduler::MAX_THREADS,
            )),
            threads: spin::Mutex::new(hashbrown::HashMap::with_capacity(SmpScheduler::MAX_THREADS)),
            upcalls,
            tid_counter: AtomicUsize::new(0),
            per_core: arr![SchedulerCoreState::new(); 96], // MAX_CORES
            irqvec_to_tid: spin::Mutex::new(hashbrown::HashMap::with_capacity(8)),
        }
    }

    /// Returns true as long as we have 'active', unfinished thread.
    ///
    /// A thread that is currently blocked/waiting still counts as active.
    ///
    /// TODO(correctness): Maybe we want to exclude interrupt threads:
    /// e.g., self.threads.lock().len() - self.irqvec_to_tid.lock().len() > 0
    /// TODO(api): Probably needs a better API, maybe schedule() should just return
    /// the next time a thread becomes runnable if none are, or a set of IRQs to wait on...
    pub fn has_active_threads(&self) -> bool {
        self.threads.lock().len() > 0
    }

    pub fn spawn_with_args<F>(
        &self,
        stack: LineupStack,
        f: F,
        arg: *mut u8,
        affinity: kpi::system::GlobalThreadId,
        interrupt_vector: Option<IrqVector>,
        tls: *mut ThreadControlBlock<'static>,
    ) -> Option<ThreadId>
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let t = self.tid_counter.fetch_add(1, Ordering::Relaxed);
        let tid = ThreadId(t);
        let core_id = crate::gtid_to_core_id(affinity);

        let (handle, generator) = unsafe {
            Thread::new(
                tid,
                core_id,
                stack,
                f,
                arg,
                self.upcalls,
                interrupt_vector,
                tls,
            )
        };

        self.add_thread(handle, generator).map(|tid| {
            self.mark_runnable(tid, core_id);
            if let Some(vec) = interrupt_vector {
                self.irqvec_to_tid.lock().insert(vec, tid);
            }
            tid
        })
    }

    pub fn spawn<F>(
        &self,
        stack_size: usize,
        f: F,
        arg: *mut u8,
        affinity: kpi::system::GlobalThreadId,
        irq_vec: Option<IrqVector>,
    ) -> Option<ThreadId>
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let stack = LineupStack::from_size(stack_size);
        let tls = unsafe { tls2::ThreadControlBlock::new_tls_area() };
        self.spawn_with_args(stack, f, arg, affinity, irq_vec, tls)
    }

    fn add_thread(
        &self,
        handle: Thread,
        generator: Generator<'a, YieldResume, YieldRequest, LineupStack>,
    ) -> Option<ThreadId> {
        let tid = handle.id;
        assert!(
            !self.threads.lock().contains_key(&tid),
            "Thread {} already exists?",
            tid
        );

        if self.threads.lock().len() <= SmpScheduler::MAX_THREADS {
            self.generators.lock().insert(tid, generator);
            self.threads.lock().insert(tid, handle);
            Some(tid)
        } else {
            error!("too many threads");
            None
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

    /// Remove a thread from the waitlist.
    ///
    /// TODO(performance): This has ugly runtime complexity.
    /// Maybe better do this right and use a linked-list after all.
    /// Another alternative: The only time when we have to do this
    /// is when the CondVar does a timedwait and someone wakes us
    /// up using `signal` and `broadcast` so we can remove calls
    /// here except in these situation if we track it better
    /// i.e. save in thread state if its waiting...
    fn waitlist_remove(&self, tid: ThreadId, affinity: CoreId) {
        let mut waiting = self.per_core[affinity].waiting.lock();
        waiting.retain(|&(_instant, wtid)| wtid != tid);
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
                let thread = self
                    .threads
                    .lock()
                    .remove(&tid)
                    .expect("Can't remove thread?");

                // Wake up all the waiters
                for (sleeping_tid, sleeping_affinity) in thread.joinlist {
                    log::debug!(
                        "{} will return from join on core {}",
                        sleeping_tid,
                        sleeping_affinity
                    );
                    self.mark_runnable(sleeping_tid, sleeping_affinity);
                }
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
                self.waitlist_remove(rtid, rtid_affinity);
                // TODO(race): We can race with the core running on core id rtid_affinity here,
                // it will remove the rtid on it's own if the wait timeout has been reached
                // so if we don't remove anything here from the waitlist we should probably not insert
                // alternative is to lock both lists, need to have a lockint scheme then
                // e.g. we could use order of rtid affinity
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
                        .get(rtid)
                        .expect("Can't find thread")
                        .affinity;
                    self.waitlist_remove(*rtid, rtid_affinity);
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
            Some(YieldRequest::JoinOn(wait_on_tid)) => {
                trace!(
                    "The thread #{:?} is waiting for #{:?} to complete.",
                    tid,
                    wait_on_tid
                );

                match self.threads.lock().get_mut(&wait_on_tid) {
                    // If we find `wait_on_tid` in self.threads, put ourselves
                    // on its thread join-waitlist
                    Some(running_thread) => {
                        running_thread.joinlist.push((tid, affinity));
                        // Return interrupted to force a context switch
                        // We will be woken up again in the thread exit
                        // logic (e.g., the None arm above)
                        //self.mark_unrunnable(tid, affinity);
                        YieldResume::Interrupted
                    }
                    // If we don't find wait_on_tid, thread has already
                    // exited, (note this implementation means we'll never
                    // reuse thread ids because otherwise we would have
                    // a race here)
                    None => YieldResume::Completed,
                }
            }
            Some(YieldRequest::Spawn(function, arg, affinity, irq_vector)) => {
                trace!("self.spawn {:?} {:p}", function, arg);
                let tid = self
                    .spawn(
                        64 * 4096,
                        move |arg| unsafe {
                            (function.unwrap())(arg);
                        },
                        arg,
                        affinity,
                        irq_vector,
                    )
                    .expect("Can't spawn the thread");
                YieldResume::Spawned(tid)
            }
            Some(YieldRequest::SpawnWithArgs(
                stack,
                function,
                arg,
                affinity,
                irq_vec,
                tls_private,
            )) => {
                trace!("self.spawn {:?} {:p}", function, arg);
                let tid = self
                    .spawn_with_args(
                        stack,
                        move |arg| unsafe {
                            (function.unwrap())(arg);
                        },
                        arg,
                        affinity,
                        irq_vec,
                        tls_private,
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

    /// Check for an incoming interrupt.
    fn check_interrupt(&self, state: &SchedulerControlBlock) {
        while !state.pending_irqs.is_empty() {
            match state.pending_irqs.pop() {
                Some(vec) => match self.irqvec_to_tid.lock().get(&vec) {
                    Some(tid) => self.mark_runnable(*tid, state.core_id),
                    None => error!("Don't have a thread to handle IRQ vector {}", vec),
                },
                None => unreachable!("Only one thread pops so this shouldn't happen"),
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

        let mut prev_rumprun_lwp: *mut u8 = ptr::null_mut();
        // Run until `runnable` is empty.
        loop {
            self.check_interrupt(scb);
            self.check_wakeups(core_id);

            // The next thread ID we want to run
            let next_tid = self.per_core[core_id].runnable.lock().pop_front();
            match next_tid {
                Some(tid) => {
                    let mut generator = self
                        .generators
                        .lock()
                        .remove(&tid)
                        .expect("Can't find generator thread state?");

                    let mut resume_action: YieldResume = {
                        let thread_map = self.threads.lock();
                        let thread = thread_map.get(&tid).expect("Can't find thread state?");
                        trace!("Thread = {:?}", thread);

                        // TODO(api-ergonomics): `context_switch` should be a generic (non-rump specific) interface
                        unsafe {
                            let next_rumprun_lwp = (*thread.state).rumprun_lwp as *mut u8;
                            (self.upcalls.context_switch)(prev_rumprun_lwp, next_rumprun_lwp);
                            prev_rumprun_lwp = next_rumprun_lwp;
                        }
                        // Switch the TCB to the new thread:
                        unsafe {
                            tls2::arch::set_tcb(thread.state);
                        }
                        thread.return_with.unwrap_or(YieldResume::Completed)
                    };

                    // Run the thread until `handle_yield_request` decides on a context-switch
                    // or the thread is done:
                    loop {
                        trace!("{:?} generator.resume = {:?}", tid, resume_action);
                        let yielded_with = generator.resume(resume_action);
                        trace!("yielded_with = {:?}", yielded_with);
                        resume_action = self.handle_yield_request(tid, yielded_with);
                        trace!("{:?} resume_action = {:?}", tid, resume_action);
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
                            trace!("Dropping generator for {}", tid);
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
            None,
        );
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                let _r = seen_threads2.push(thread::current().id());
            },
            ptr::null_mut(),
            1,
            None,
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

    /// Checks that threads can join on other threads.
    /// (In passing this also checks parameter passing to new threads)
    #[test]
    fn joining() {
        use crossbeam_queue::SegQueue;
        let _r = env_logger::try_init();

        let end_times: Arc<SegQueue<ThreadId>> = Arc::new(SegQueue::new());
        let et1 = end_times.clone();

        // Create a scheduler and reference to it
        let s: Arc<SmpScheduler> = Arc::new(Default::default());
        let s1 = s.clone();
        let s2 = s.clone();

        unsafe extern "C" fn do_nothing(arg: *mut u8) -> *mut u8 {
            let et: Arc<SegQueue<ThreadId>> = Arc::from_raw(arg as *const SegQueue<_>);
            et.push(Environment::tid());
            ptr::null_mut()
        }

        unsafe extern "C" fn spawn_more(arg: *mut u8) -> *mut u8 {
            let et: Arc<SegQueue<ThreadId>> = Arc::from_raw(arg as *const SegQueue<_>);

            let mut handles = vec![];
            for i in 0..3 {
                handles.push(
                    Environment::thread()
                        .spawn_on_core(
                            Some(do_nothing),
                            Arc::into_raw(et.clone()) as *const _ as *mut u8,
                            i % 2,
                        )
                        .unwrap(),
                );
            }

            for handle in handles {
                Environment::thread().join(handle);
            }

            et.push(Environment::tid());
            ptr::null_mut()
        }

        // Spawn a thread that spawns a bunch more threads
        // and waits until they all exit.
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                for i in 0..3 {
                    let handle = Environment::thread().spawn_on_core(
                        Some(spawn_more),
                        Arc::into_raw(et1.clone()) as *const _ as *mut u8,
                        i % 2,
                    );
                    Environment::thread().join(handle.expect("Didn't get a handle lol"));
                }
                et1.push(Environment::tid());
            },
            ptr::null_mut(),
            0,
            None,
        );

        // Spawn two pthreads each will dispatch lineup threads from "two cores"
        // to test concurrency
        let t1 = thread::spawn(move || {
            let scb1: SchedulerControlBlock = SchedulerControlBlock::new(0);
            let start = Instant::now();
            while start.elapsed().as_secs() < 2 {
                s1.run(&scb1);
            }
        });

        let t2 = thread::spawn(move || {
            let scb2: SchedulerControlBlock = SchedulerControlBlock::new(1);
            let start = Instant::now();
            while start.elapsed().as_secs() < 2 {
                s2.run(&scb2);
            }
        });
        let _r = t1.join();
        let _r = t2.join();

        // The join invariant for tids should be (a -> b = a finishes before b):
        // [ [#2, #3, #4] -> #1 ->
        //   [#6, #7, #8] -> #5 ->
        //   [#10, #11, #12] -> #9 -> # 0 ]
        assert_eq!(end_times.len(), 13);

        let mut group = [
            end_times.pop().unwrap(),
            end_times.pop().unwrap(),
            end_times.pop().unwrap(),
        ];
        group.sort();
        assert_eq!(group, [ThreadId(2), ThreadId(3), ThreadId(4)]);
        assert_eq!(end_times.pop().unwrap(), ThreadId(1));

        let mut group = [
            end_times.pop().unwrap(),
            end_times.pop().unwrap(),
            end_times.pop().unwrap(),
        ];
        group.sort();
        assert_eq!(group, [ThreadId(6), ThreadId(7), ThreadId(8)]);
        assert_eq!(end_times.pop().unwrap(), ThreadId(5));

        let mut group = [
            end_times.pop().unwrap(),
            end_times.pop().unwrap(),
            end_times.pop().unwrap(),
        ];
        group.sort();
        assert_eq!(group, [ThreadId(10), ThreadId(11), ThreadId(12)]);
        assert_eq!(end_times.pop().unwrap(), ThreadId(9));

        assert_eq!(end_times.pop().unwrap(), ThreadId(0));
    }

    /// Checks that the scheduler can run in parallel.
    ///
    /// Running two long computations on two cores shouldn't take
    /// longer than running just one on one core.
    #[test]
    #[ignore = "Fix cpuid/time on AMD machines"]
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
        let the_prime: u64 = 96001891;
        let ref_start = Instant::now();
        let r = core::hint::black_box(is_prime(the_prime));
        let ref_end = Instant::now();

        // Spawn two lineup threads (with two underlying pthreads), each thread computes is_prime
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                core::hint::black_box(is_prime(the_prime));
            },
            ptr::null_mut(),
            0,
            None,
        );
        s.spawn(
            DEFAULT_STACK_SIZE_BYTES,
            move |_| {
                core::hint::black_box(is_prime(the_prime));
            },
            ptr::null_mut(),
            1,
            None,
        );

        // Spawn two pthreads each will dispatch lineup threads from "two cores"
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
        #[cfg(debug_assertions)]
        let bound = Duration::from_millis(500);
        #[cfg(not(debug_assertions))]
        let bound = Duration::from_millis(100);

        assert!(exp_duration >= ref_duration - bound, "Lineup was too fast?");
        assert!(exp_duration <= ref_duration + bound, "Lineup was too slow?");
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
    #[ignore = "Fix cpuid/time on AMD machines"]
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
            None,
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
            None,
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
            trace!("got tid {:?} instant {:?}", tid, instant);
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
