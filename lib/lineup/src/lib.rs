//!  A user-space thread scheduler with support for synchronization primitives.

#![feature(vec_remove_item)]
#![feature(drain_filter)]
#![feature(linkage)]
#![feature(ptr_offset_from)]
#![feature(thread_local)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod condvar;
pub mod mutex;
pub mod rwlock;
pub mod scheduler;
pub mod semaphore;
pub mod stack;
pub mod threads;
pub mod tls2;
pub mod upcalls;

/// Type to represent a core id for the scheduler.
type CoreId = usize;
