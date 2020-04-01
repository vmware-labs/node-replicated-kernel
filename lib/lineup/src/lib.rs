//!  A user-space thread scheduler with support for synchronization primitives.

#![feature(vec_remove_item)]
#![feature(drain_filter)]
#![feature(linkage)]
#![feature(ptr_offset_from)]
#![feature(thread_local)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::fmt;

pub use alloc::boxed::Box;
pub use alloc::collections::VecDeque;
pub use alloc::sync::Arc;
pub use alloc::vec::Vec;
pub use hashbrown::HashMap;

pub mod condvar;
pub mod mutex;
pub mod rwlock;
pub mod semaphore;
pub mod scheduler;
pub mod stack;
pub mod tls2;
pub mod threads;

use crate::tls2::ThreadControlBlock;
use stack::LineupStack;

/// Type to represent a core id for the scheduler.
type CoreId = usize;

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


