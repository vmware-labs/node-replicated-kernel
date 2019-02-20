#![feature(vec_remove_item, linkage, alloc)]
#![cfg_attr(not(test), no_std)]
#![allow(unused)]

extern crate either;
extern crate fringe;
extern crate hashmap_core;
extern crate log;
extern crate rawtime;
extern crate x86;

use core::fmt;
use rawtime::Instant;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
mod ds {
    pub use hashmap_core::map::HashMap;
    pub use std::sync::Arc;
    pub use std::vec::Vec;
}

#[cfg(not(test))]
mod ds {
    extern crate alloc;
    pub use alloc::boxed::Box;
    pub use alloc::sync::Arc;
    pub use alloc::vec::Vec;
    pub use hashmap_core::map::HashMap;
}

use core::hash::{Hash, Hasher};
use core::ops::Add;
use core::ptr;
use core::time::Duration;
use log::*;

use fringe::generator::{Generator, Yielder};
use fringe::OwnedStack;

pub mod condvar;
pub mod mutex;
pub mod rwlock;
pub mod tls;

fn noop_curlwp() -> u64 {
    0
}

fn noop_unschedule(_nlocks: &mut u64, _mtx: Option<&mutex::Mutex>) {}

fn noop_schedule(_nlocks: &u64, _mtx: Option<&mutex::Mutex>) {}

pub static DEFAULT_UPCALLS: Upcalls = Upcalls {
    curlwp: noop_curlwp,
    schedule: noop_schedule,
    deschedule: noop_unschedule,
};

#[derive(Debug, Clone, Copy)]
pub struct Upcalls {
    pub curlwp: fn() -> u64,
    pub schedule: fn(&u64, Option<&mutex::Mutex>),
    pub deschedule: fn(&mut u64, Option<&mutex::Mutex>),
}

#[derive(Debug)]
pub enum Error {
    Interrupted,
    TimedOut,
}

#[derive(Debug, PartialEq)]
enum YieldRequest {
    None,
    Timeout(Instant),
    Runnable(ThreadId),
    Unrunnable(ThreadId),
    RunnableList(ds::Vec<ThreadId>),
    Spawn(
        Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        *mut u8,
    ),
}

unsafe impl Send for YieldRequest {}

#[derive(Debug)]
enum YieldResume {
    Completed,
    TimedOut,
    Interrupted,
    Spawned(ThreadId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadId(usize);

impl Hash for ThreadId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub struct Thread {
    id: ThreadId,
    wait_until: Option<Instant>,
    interrupted: bool,
    state: *mut ThreadState<'static>, // TODO: not really static, but keeps it easier for now
}

impl Thread {
    unsafe fn new<'a, F>(
        tid: ThreadId,
        stack_size: usize,
        f: F,
        arg: *mut u8,
        upcalls: Upcalls,
    ) -> (Thread, Generator<'a, YieldResume, YieldRequest, OwnedStack>)
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let stack = OwnedStack::new(stack_size);

        let thread = Thread {
            id: tid,
            wait_until: None,
            interrupted: false,
            state: ptr::null_mut(),
        };

        let generator = Generator::unsafe_new(stack, move |yielder, _| {
            let mut ts = ThreadState {
                tid: tid,
                yielder: yielder,
                upcalls: upcalls,
                rump_lwp: ptr::null_mut(),
            };
            tls::set_thread_state((&mut ts) as *mut ThreadState);
            let r = f(arg);
            tls::set_thread_state(ptr::null_mut() as *mut ThreadState);
            r
        });

        (thread, generator)
    }

    pub fn interrupt(&mut self) {
        self.interrupted = true
    }
}

impl PartialEq for Thread {
    fn eq(&self, other: &Thread) -> bool {
        self.id.0 == other.id.0
    }
}

impl Eq for Thread {}

impl Hash for Thread {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

pub struct Scheduler<'a> {
    threads: ds::HashMap<ThreadId, (Thread, Generator<'a, YieldResume, YieldRequest, OwnedStack>)>,
    runnable: ds::Vec<ThreadId>,
    run_idx: usize,
    tid_counter: usize,
    upcalls: Upcalls,
    state: tls::SchedulerState,
}

impl<'a> Scheduler<'a> {
    pub const MAX_THREADS: usize = 64;

    pub fn new(upcalls: Upcalls) -> Scheduler<'a> {
        Scheduler {
            threads: ds::HashMap::with_capacity(Scheduler::MAX_THREADS),
            runnable: ds::Vec::with_capacity(Scheduler::MAX_THREADS),
            run_idx: 0,
            tid_counter: 0,
            upcalls: upcalls,
            state: tls::SchedulerState::new(),
        }
    }

    fn add_thread(
        &mut self,
        handle: Thread,
        generator: Generator<'a, YieldResume, YieldRequest, OwnedStack>,
    ) -> Option<ThreadId> {
        let tid = handle.id.clone();
        assert!(
            !self.threads.contains_key(&tid),
            "Thread {} already exists?",
            tid
        );

        if self.threads.len() <= Scheduler::MAX_THREADS {
            self.threads.insert(tid, (handle, generator));
            Some(tid)
        } else {
            return None;
        }
    }

    fn mark_runnable(&mut self, tid: ThreadId) {
        assert!(
            self.threads.contains_key(&tid),
            "Thread {} does not exist?",
            tid
        );
        assert!(
            !self.runnable.contains(&tid),
            "Thread {} is already runnable?",
            tid
        );
        self.runnable.push(tid);
    }

    fn mark_unrunnable(&mut self, tid: ThreadId) {
        trace!("Removing Thread {} from run-list.", tid);

        assert!(
            self.threads.contains_key(&tid),
            "Thread {} does not exist?",
            tid
        );
        assert!(
            self.runnable.contains(&tid),
            "Thread {} is not runnable?",
            tid
        );

        self.runnable
            .remove_item(&tid)
            .expect("Thread is not runnable?");
    }

    fn reset_run_index(&mut self) {
        self.run_idx = 0;
    }

    pub fn spawn<F>(&mut self, stack_size: usize, f: F, arg: *mut u8) -> Option<ThreadId>
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let tid = ThreadId(self.tid_counter);
        let (handle, generator) = unsafe { Thread::new(tid, stack_size, f, arg, self.upcalls) };

        self.add_thread(handle, generator).map(|tid| {
            self.mark_runnable(tid);
            self.tid_counter += 1;
            tid
        })
    }

    pub fn run(&mut self) {
        if self.runnable.is_empty() {
            return;
        }

        let start_idx = self.run_idx;
        let now = Instant::now();
        loop {
            trace!(
                "self.runnable({}) = {:?}",
                self.runnable.len(),
                self.runnable
            );
            let tid = self.runnable[self.run_idx];

            trace!(
                "self.runnable({}) = {:?}, dispatching {:?}",
                self.runnable.len(),
                self.runnable,
                tid
            );

            let action: YieldResume = {
                let thread: &mut Thread = &mut self
                    .threads
                    .get_mut(&tid)
                    .expect("Can't find thread state?")
                    .0;

                if thread.interrupted {
                    thread.interrupted = false;
                    YieldResume::Interrupted
                } else if thread.wait_until == None {
                    YieldResume::Completed
                } else if thread
                    .wait_until
                    .map(|instant| now >= instant)
                    .unwrap_or(false)
                {
                    thread.wait_until = None;
                    YieldResume::TimedOut
                } else {
                    self.run_idx = (self.run_idx + 1) % self.runnable.len();
                    if self.run_idx == start_idx {
                        trace!("Checked all threads in runnable.");
                        break;
                    }
                    continue;
                }
            };

            let mut tls = tls::ThreadLocalStorage::new();
            unsafe {
                let thread: &mut Thread = &mut self
                    .threads
                    .get_mut(&tid)
                    .expect("Can't find thread state?")
                    .0;

                tls::arch::set_tls((&mut tls) as *mut tls::ThreadLocalStorage);
                tls::set_scheduler_state((&mut self.state) as *mut tls::SchedulerState);

                // if this is the first time we run this,
                // we should not overwrite thread state
                // the thread will do it for us.
                if !thread.state.is_null() {
                    tls::set_thread_state(thread.state);
                }
            }

            let result = {
                let generator = &mut self.threads.get_mut(&tid).unwrap().1;
                generator.resume(action)
            };

            let (is_done, cycle_to_next_thread) = match result {
                None => {
                    trace!("Thread {} has terminated.", tid);
                    self.mark_unrunnable(tid);
                    self.threads.remove(&tid);
                    self.reset_run_index();
                    unsafe {
                        tls::arch::set_tls(ptr::null_mut());
                    }
                    (true, true)
                }
                Some(YieldRequest::None) => (false, true),
                Some(YieldRequest::Runnable(rtid)) => {
                    trace!("YieldRequest::Runnable {:?}", rtid);
                    self.mark_runnable(rtid);
                    self.run_idx -= 1;
                    (false, false)
                }
                Some(YieldRequest::Unrunnable(rtid)) => {
                    trace!("YieldRequest::Unrunnable {:?}", rtid);
                    self.mark_unrunnable(rtid);
                    self.reset_run_index();
                    (false, rtid == tid)
                }
                Some(YieldRequest::RunnableList(rtids)) => {
                    trace!("YieldRequest::RunnableList {:?}", rtids);
                    for rtid in rtids.iter() {
                        self.mark_runnable(*rtid);
                    }
                    //self.reset_run_index();
                    self.run_idx = self.runnable.len() - 1;
                    (false, rtids.contains(&tid))
                }
                Some(YieldRequest::Timeout(instant)) => {
                    // The thread has suspended itself.
                    let thread: &mut Thread = &mut self
                        .threads
                        .get_mut(&tid)
                        .expect("Can't find thread state?")
                        .0;
                    thread.wait_until = Some(instant);
                    (false, true)
                }
                Some(YieldRequest::Spawn(function, arg)) => {
                    trace!("self.spawn {:?} {:p}", function, arg);
                    self.spawn(
                        64 * 4096,
                        move |arg| unsafe {
                            (function.unwrap())(arg);
                        },
                        arg,
                    )
                    .map(|tid| {
                        trace!("self.spawned {:?}", tid);
                    });
                    (false, false)
                }
            };

            // If thread is not done we need to preserve TLS
            // TODO: I modified libfringe to do this, but not
            // sure if llvm actually does it, check assembly!
            if !is_done {
                let thread: &mut Thread = &mut self
                    .threads
                    .get_mut(&tid)
                    .expect("Can't find thread state?")
                    .0;

                unsafe {
                    thread.state = tls::get_thread_state();
                    tls::arch::set_tls(ptr::null_mut());
                }
            }

            if cycle_to_next_thread {
                self.run_idx = (self.run_idx + 1) % self.runnable.len();
                trace!("Try to schedule self.run_idx {} next.", self.run_idx);
                if self.run_idx == start_idx {
                    trace!("Checked all threads in runnable.");
                    break;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreadState<'a> {
    yielder: &'a Yielder<YieldResume, YieldRequest>,
    tid: ThreadId,
    pub upcalls: Upcalls,
    pub rump_lwp: *const u64,
}

impl<'a> ThreadState<'a> {
    fn yielder(&self) -> &'a Yielder<YieldResume, YieldRequest> {
        self.yielder
    }

    pub fn set_lwp(&mut self, lwp_ptr: *const u64) {
        self.rump_lwp = lwp_ptr;
    }

    pub fn spawn(
        &self,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
    ) -> Option<ThreadId> {
        let request = YieldRequest::Spawn(f, arg);
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn sleep(&self, d: Duration) {
        let request = YieldRequest::Timeout(Instant::now().add(d));
        self.yielder().suspend(request);
    }

    fn make_runnable(&self, tid: ThreadId) {
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
