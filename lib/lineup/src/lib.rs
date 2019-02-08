#![feature(vec_remove_item, linkage, alloc)]
#![cfg_attr(not(test), no_std)]
#![allow(unused)]

extern crate either;
extern crate fringe;
extern crate hashmap_core;
extern crate log;
extern crate rawtime;
extern crate x86;

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
    state: *mut ThreadState<'static>, // TODO: not really static, but keeps it easier for now
}

impl Thread {
    unsafe fn new<'a, F>(
        tid: ThreadId,
        stack_size: usize,
        f: F,
        upcalls: Upcalls,
    ) -> (Thread, Generator<'a, YieldResume, YieldRequest, OwnedStack>)
    where
        F: 'static + FnOnce(ThreadState) + Send,
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
            };
            tls::set_thread_state((&mut ts) as *mut ThreadState);
            let r = f(ts);
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
        F: 'static + FnOnce(ThreadState) + Send,
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
                let thread: &mut Thread = &mut self
                    .threads
                    .get_mut(&tid)
                    .expect("Can't find thread state?")
                    .0;
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

            match result {
                None => {
                    // The thread has terminated.
                    self.threads.remove(&tid);
                    self.runnable.remove(self.run_idx);
                    self.run_idx = 0;
                    unsafe {
                        tls::set_thread_state(ptr::null_mut());
                    }
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

            // If thread is not done we need to preserve TLS
            // TODO: I modified libfringe to do this, but not sure if llvm actually does it, check assembly!
            if result.is_some() {
                let thread: &mut Thread = &mut self
                    .threads
                    .get_mut(&tid)
                    .expect("Can't find thread state?")
                    .0;

                unsafe {
                    thread.state = tls::get_thread_state();
                    tls::set_thread_state(ptr::null_mut());
                }
            }

            break;
        }
    }
}

#[derive(Clone)]
pub struct ThreadState<'a> {
    yielder: &'a Yielder<YieldResume, YieldRequest>,
    tid: ThreadId,
    pub upcalls: Upcalls,
}

impl<'a> ThreadState<'a> {
    fn yielder(&self) -> &'a Yielder<YieldResume, YieldRequest> {
        self.yielder
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

#[test]
fn has_fs_gs_base_instructions() {
    env_logger::init();
    let cpuid = x86::cpuid::CpuId::new();
    assert!(cpuid
        .get_extended_feature_info()
        .map_or(false, |ef| ef.has_fsgsbase()));
    /*debug!("gsbase is {}", unsafe {
        x86::bits64::segmentation::rdgsbase()
    });*/
}
