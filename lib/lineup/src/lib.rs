//!  A user-space thread scheduler with support for synchronization primitives.

#![feature(vec_remove_item)]
#![feature(drain_filter)]
#![feature(linkage)]
#![feature(ptr_offset_from)]
#![feature(thread_local)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::fmt;
use rawtime::Instant;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
mod ds {
    pub use hashbrown::HashMap;
    pub use std::collections::VecDeque;
    pub use std::sync::Arc;
    pub use std::vec::Vec;
}

#[cfg(not(test))]
mod ds {
    pub use alloc::boxed::Box;
    pub use alloc::collections::VecDeque;
    pub use alloc::sync::Arc;
    pub use alloc::vec::Vec;
    pub use hashbrown::HashMap;
}

use core::hash::{Hash, Hasher};
use core::ptr;
use log::*;

use fringe::generator::Generator;

pub mod condvar;
pub mod mutex;
pub mod rwlock;
pub mod semaphore;
pub mod smp;
pub mod stack;
pub mod tls2;

use crate::tls2::ThreadControlBlock;
use stack::LineupStack;

/// Default stack size in bytes.
pub const DEFAULT_STACK_SIZE_BYTES: usize = 32 * 4096;

fn noop_curlwp() -> u64 {
    0
}

fn noop_unschedule(_nlocks: &mut i32, _mtx: Option<&mutex::Mutex>) {}

fn noop_schedule(_nlocks: &i32, _mtx: Option<&mutex::Mutex>) {}

pub static DEFAULT_UPCALLS: Upcalls = Upcalls {
    curlwp: noop_curlwp,
    schedule: noop_schedule,
    deschedule: noop_unschedule,
};

/// Notification up-calls from the scheduler to the application
/// (here to support the rump runtime).
#[derive(Clone, Copy)]
pub struct Upcalls {
    pub curlwp: fn() -> u64,
    pub schedule: fn(&i32, Option<&mutex::Mutex>),
    pub deschedule: fn(&mut i32, Option<&mutex::Mutex>),
}

impl fmt::Debug for Upcalls {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Upcalls {{}}")
    }
}

/// Requests back to from the thread-context to the scheduler.
#[derive(Debug, PartialEq)]
enum YieldRequest {
    /// Just yield for now?
    None,
    /// Block thread until we reach Instant.
    Timeout(Instant),
    /// Tell scheduler to make ThreadId runnable.
    Runnable(ThreadId),
    /// Tell scheduler to make ThreadId unrunnable.
    Unrunnable(ThreadId),
    /// Make everything in the given list runnable.
    RunnableList(ds::Vec<ThreadId>),
    /// Spawn a new thread that runs the provided function and argument.
    Spawn(
        Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        *mut u8,
        CoreId,
    ),
    /// Spawn a new thread that runs function/argument on the provided stack.
    SpawnWithStack(
        LineupStack,
        Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        *mut u8,
        CoreId,
    ),
}

//unsafe impl Send for YieldRequest {}
type CoreId = usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YieldResume {
    /// The request was completed (we immediately resumed without a context switch).
    Completed,
    /// The thread was done (and is resumed now after a context switch).
    Interrupted,
    /// A child thread was spawned with the given ThreadId.
    Spawned(ThreadId),
    /// Thread has completed (and has been removed from the scheduler state)
    DoNotResume,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ThreadId(pub usize);

impl Hash for ThreadId {
    /// For hashing we only rely on the ID as the affinity can change.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ThreadId {{ id={} }}", self.0)
    }
}

pub struct Thread {
    id: ThreadId,
    affinity: CoreId,
    return_with: Option<YieldResume>,

    /// Storage to remember the pointer to the TCB
    ///
    /// If a thread runs the first time this is null since a thread creates
    /// it's own TCB before running. After the first yield this will
    /// be used to memorize it for future resumes.
    ///
    /// TODO(correctness): It's not really static (it's on the thread's stack),
    /// but keeps it easier for now.
    state: *mut ThreadControlBlock<'static>,
}

impl fmt::Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Thread#{}", self.id.0)
    }
}

impl Thread {
    unsafe fn new<'a, F>(
        tid: ThreadId,
        affinity: CoreId,
        stack: LineupStack,
        f: F,
        arg: *mut u8,
        upcalls: Upcalls,
    ) -> (
        Thread,
        Generator<'a, YieldResume, YieldRequest, LineupStack>,
    )
    where
        F: 'static + FnOnce(*mut u8) + Send,
    {
        let thread = Thread {
            id: tid,
            affinity,
            return_with: None,
            state: ptr::null_mut(),
        };

        let generator = Generator::unsafe_new(stack, move |yielder, _| {
            let mut ts = tls2::ThreadControlBlock {
                tid,
                yielder,
                upcalls,
                current_core: affinity,
                rump_lwp: ptr::null_mut(),
                rumprun_lwp: ptr::null_mut(),
            };

            // Install TCB/TLS
            tls2::arch::set_tcb((&mut ts) as *mut ThreadControlBlock);

            let r = f(arg);

            // Reset TCB/TLS once thread completes
            tls2::arch::set_tcb(ptr::null_mut() as *mut ThreadControlBlock);

            r
        });

        (thread, generator)
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
