#![feature(vec_remove_item, linkage, alloc)]
#![cfg_attr(not(test), no_std)]
#![allow(unused)]

extern crate either;
extern crate fringe;
extern crate hashmap_core;
extern crate log;
extern crate rawtime;

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
    pub use alloc::sync::Arc;
    pub use alloc::vec::Vec;
    pub use hashmap_core::map::HashMap;
}

use core::hash::{Hash, Hasher};
use core::ops::Add;
use core::time::Duration;
use log::*;

use fringe::generator::{Generator, Yielder};
use fringe::OwnedStack;

pub mod condvar;
pub mod mutex;
pub mod rwlock;

#[cfg(test)]
fn noop_curlwp() -> u64 {
    0
}

#[cfg(test)]
fn noop_unschedule(_nlocks: &mut u64, _mtx: Option<&mutex::Mutex>) {}

#[cfg(test)]
fn noop_schedule(_nlocks: &u64, _mtx: Option<&mutex::Mutex>) {}

#[cfg(test)]
static DEFAULT_UPCALLS: Upcalls = Upcalls {
    curlwp: noop_curlwp,
    schedule: noop_schedule,
    deschedule: noop_unschedule,
};

#[derive(Debug, Clone, Copy)]
pub struct Upcalls {
    curlwp: fn() -> u64,
    schedule: fn(&u64, Option<&mutex::Mutex>),
    deschedule: fn(&mut u64, Option<&mutex::Mutex>),
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
}

unsafe impl Send for YieldRequest {}

#[derive(Debug)]
enum YieldResume {
    Completed,
    TimedOut,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadId(usize);

impl Hash for ThreadId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[derive(Debug)]
pub struct Thread {
    id: ThreadId,
    wait_until: Option<Instant>,
    interrupted: bool,
}

impl Thread {
    unsafe fn new<'a, F>(
        tid: ThreadId,
        stack_size: usize,
        f: F,
        upcalls: Upcalls,
    ) -> (Thread, Generator<'a, YieldResume, YieldRequest, OwnedStack>)
    where
        F: 'static + FnOnce(SchedControl) + Send,
    {
        let stack = OwnedStack::new(stack_size);

        (
            Thread {
                id: tid,
                wait_until: None,
                interrupted: false,
            },
            Generator::unsafe_new(stack, move |yielder, _| {
                f(SchedControl {
                    yielder: Some(yielder),
                    upcalls: upcalls,
                })
            }),
        )
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
        }
    }

    pub fn spawn<F>(&mut self, stack_size: usize, f: F) -> ThreadId
    where
        F: 'static + FnOnce(SchedControl) + Send,
    {
        let tid = ThreadId(self.tid_counter);
        let (handle, generator) = unsafe { Thread::new(tid, stack_size, f, self.upcalls) };
        self.threads.insert(tid, (handle, generator));
        self.runnable.push(tid);

        self.tid_counter += 1;
        assert!(self.threads.len() == self.tid_counter);

        tid
    }

    pub fn run(&mut self) {
        if self.runnable.is_empty() {
            return;
        }

        let now = Instant::now();
        let start_idx = self.run_idx;
        loop {
            trace!(
                "self.runnable({}) = {:?}",
                self.runnable.len(),
                self.runnable
            );
            self.run_idx = (self.run_idx + 1) % self.runnable.len();
            let tid = self.runnable[self.run_idx];

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
                } else if self.run_idx == start_idx {
                    // Checked all threads in runnable.
                    break;
                } else {
                    continue;
                }
            };

            unsafe {
                ENV.tid = Some(tid);
            }

            let generator = &mut self.threads.get_mut(&tid).unwrap().1;
            let result = generator.resume(action);

            match result {
                None => {
                    // The thread has terminated.
                    self.threads.remove(&tid);
                    self.runnable.remove(self.run_idx);
                    self.run_idx = 0;
                }
                Some(YieldRequest::None) => {}
                Some(YieldRequest::Runnable(rtid)) => {
                    assert!(self.threads.contains_key(&rtid));
                    self.runnable.push(rtid);
                }
                Some(YieldRequest::Unrunnable(rtid)) => {
                    assert!(self.threads.contains_key(&rtid));
                    self.runnable.remove_item(&rtid);
                    self.run_idx = 0;
                }
                Some(YieldRequest::Timeout(instant)) => {
                    // The thread has suspended itself.
                    let thread: &mut Thread = &mut self
                        .threads
                        .get_mut(&tid)
                        .expect("Can't find thread state?")
                        .0;
                    thread.wait_until = Some(instant);
                }
            }

            break;
        }
    }
}

#[derive(Clone)]
pub struct SchedControl<'a> {
    yielder: Option<&'a Yielder<YieldResume, YieldRequest>>,
    pub upcalls: Upcalls,
}

impl<'a> SchedControl<'a> {
    fn yielder(&self) -> &'a Yielder<YieldResume, YieldRequest> {
        self.yielder.expect("Can not suspend origin thread")
    }

    pub fn sleep(&self, d: Duration) {
        let request = YieldRequest::Timeout(Instant::now().add(d));
        self.yielder().suspend(request);
    }

    fn make_runnable(&self, tid: ThreadId) {
        let request = YieldRequest::Runnable(tid);
        self.yielder().suspend(request);
    }

    fn make_all_runnable(&self, _tids: ds::Vec<ThreadId>) {
        unreachable!("make_all_runnable")
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

pub struct Environment {
    tid: Option<ThreadId>,
}

impl Environment {
    pub fn current_tid(&self) -> Option<ThreadId> {
        self.tid
    }
}

static mut ENV: Environment = Environment { tid: None };
