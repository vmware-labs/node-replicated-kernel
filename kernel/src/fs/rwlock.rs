// Copyright © 2019-2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The distributed readers-writer lock used by the replica.
//!
//! This module is only public since it needs to be exposed to the benchmarking
//! code. For clients there is no need to rely on this directly, as the RwLock
//! is embedded inside the Replica.

use core::cell::UnsafeCell;
use core::default::Default;
use core::fmt::{Debug, Error, Formatter};
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::arch::MAX_CORES;

use crossbeam_utils::CachePadded;

/// Maximum number of reader threads that this lock supports.
const MAX_READER_THREADS: usize = MAX_CORES;
static_assertions::const_assert!(MAX_READER_THREADS > 0);

/// Default `rlock` member, used for array initialization
#[allow(clippy::declare_interior_mutable_const)]
const DEFAULT_RLOCK: CachePadded<AtomicUsize> = CachePadded::new(AtomicUsize::new(0));

/// A scalable reader-writer lock.
///
/// This lock favours reader performance over writers. Each reader thread gets
/// its own "lock" while writers share a single lock.
///
/// `T` represents the underlying type protected by the lock.
/// Calling `read()` returns a read-guard that can be used to safely read `T`.
/// Calling `write()` returns a write-guard that can be used to safely mutate `T`.
pub(crate) struct RwLock<T>
where
    T: Sized + Sync,
{
    /// The writer lock. There can be at most one writer at any given point of time.
    wlock: CachePadded<AtomicBool>,

    /// Each reader use an individual lock to access the underlying data-structure.
    rlock: [CachePadded<AtomicUsize>; MAX_READER_THREADS],

    /// The underlying data-structure.
    data: UnsafeCell<T>,
}

/// A read-guard that can be used to read the underlying data structure. Writes on
/// the data structure will be blocked as long as one of these is lying around.
pub(crate) struct ReadGuard<'a, T: ?Sized + Default + Sync + 'a> {
    /// Id of the thread that acquired this guard. Required at drop time so that
    /// we can release the appropriate read lock.
    tid: usize,

    /// A reference to the Rwlock wrapping the data-structure.
    lock: &'a RwLock<T>,
}

/// A write-guard that can be used to write to the underlying data structure. All
/// reads will be blocked until this is dropped.
pub(crate) struct WriteGuard<'a, T: ?Sized + Default + Sync + 'a> {
    /// A reference to the Rwlock wrapping the data-structure.
    lock: &'a RwLock<T>,
}

impl<T> Default for RwLock<T>
where
    T: Sized + Default + Sync,
{
    /// Returns a new instance of a RwLock. Default constructs the
    /// underlying data structure.
    fn default() -> RwLock<T> {
        RwLock {
            wlock: CachePadded::new(AtomicBool::new(false)),
            rlock: [DEFAULT_RLOCK; MAX_READER_THREADS],
            data: UnsafeCell::new(T::default()),
        }
    }
}

/// This is to debug MlnrFS.
impl<T: ?Sized + Default + Sync + Debug> Debug for RwLock<T> {
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), Error> {
        todo!()
    }
}

impl<T> RwLock<T>
where
    T: Sized + Sync,
{
    /// Creates a new instance of an `RwLock<T>` which is unlocked.
    pub(crate) fn new(t: T) -> RwLock<T> {
        RwLock {
            wlock: CachePadded::new(AtomicBool::new(false)),
            rlock: [DEFAULT_RLOCK; MAX_READER_THREADS],
            data: UnsafeCell::new(t),
        }
    }
}

impl<T> RwLock<T>
where
    T: Sized + Default + Sync,
{
    /// Locks the underlying data-structure for writes. The caller can retrieve
    /// a mutable reference from the returned `WriteGuard`.
    pub(crate) fn write(&self) -> WriteGuard<T> {
        let n: usize = *crate::environment::CORES_PER_NUMA_NODE;
        // First, wait until we can acquire the writer lock.
        //while self.wlock.compare_and_swap(false, true, Ordering::Acquire) {
        loop {
            match self.wlock.compare_exchange_weak(
                false,
                true,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_x) => continue,
            }
        }

        // Next, wait until all readers have released their locks. This condition
        // evaluates to true if each reader lock is free (i.e equal to zero).
        while !self
            .rlock
            .iter()
            .take(n)
            .all(|item| item.load(Ordering::Relaxed) == 0)
        {
            spin_loop();
        }

        unsafe { WriteGuard::new(self) }
    }

    /// Locks the underlying data-structure for reads. Allows multiple readers to acquire the lock.
    /// Blocks until there aren't any active writers.
    pub(crate) fn read(&self) -> ReadGuard<T> {
        // TODO(rackscale): this method works since (currently) cnrfs replicas aren't shared across machines.
        // To have a replica used across machines we'd need to use a rack-unique identifier.
        let tid: usize = kpi::system::mtid_from_gtid(*crate::environment::CORE_ID);

        // We perform a small optimization. Before attempting to acquire a read lock, we issue
        // naked reads to the write lock and wait until it is free. For that, we retrieve a
        // raw pointer to the write lock over here.
        let ptr = unsafe {
            &*(&self.wlock as *const crossbeam_utils::CachePadded<core::sync::atomic::AtomicBool>
                as *const bool)
        };

        loop {
            // First, wait until the write lock is free. This is the small
            // optimization spoken of earlier.
            unsafe {
                while core::ptr::read_volatile(ptr) {
                    spin_loop();
                }
            }

            // Next, acquire this thread's read lock and actually check if the write lock
            // is free. If it is, then we're good to go because any new writers will now
            // see this acquired read lock and block. If it isn't free, then we got unlucky;
            // release the read lock and retry.
            self.rlock[tid].fetch_add(1, Ordering::Acquire);
            if !self.wlock.load(Ordering::Relaxed) {
                break;
            }

            self.rlock[tid].fetch_sub(1, Ordering::Release);
        }

        unsafe { ReadGuard::new(self, tid) }
    }

    /// Unlocks the write lock; invoked by the drop() method.
    pub(in crate::fs::rwlock) unsafe fn write_unlock(&self) {
        match self
            .wlock
            .compare_exchange_weak(true, false, Ordering::Acquire, Ordering::Acquire)
        {
            Ok(_) => (),
            Err(_x) => panic!("write_unlock() called without acquiring the write lock"),
        }
    }

    /// Unlocks the read lock; called by the drop() method.
    pub(in crate::fs::rwlock) unsafe fn read_unlock(&self, tid: usize) {
        if self.rlock[tid].fetch_sub(1, Ordering::Release) == 0 {
            panic!("read_unlock() called without acquiring the read lock");
        }
    }
}

impl<'rwlock, T: ?Sized + Default + Sync> ReadGuard<'rwlock, T> {
    /// Returns a read guard over a passed in reader-writer lock.
    unsafe fn new(lock: &'rwlock RwLock<T>, tid: usize) -> ReadGuard<'rwlock, T> {
        ReadGuard { tid, lock }
    }
}

impl<'rwlock, T: ?Sized + Default + Sync> WriteGuard<'rwlock, T> {
    /// Returns a write guard over a passed in reader-writer lock.
    unsafe fn new(lock: &'rwlock RwLock<T>) -> WriteGuard<'rwlock, T> {
        WriteGuard { lock }
    }
}

/// `Sync` trait allows `RwLock` to be shared between threads. The `read()` and
/// `write()` logic ensures that we will never have threads writing to and
/// reading from the underlying data structure simultaneously.
unsafe impl<T: ?Sized + Default + Sync> Sync for RwLock<T> {}

/// This `Deref` trait allows a thread to use T from a ReadGuard.
/// ReadGuard can only be dereferenced into an immutable reference.
impl<T: ?Sized + Default + Sync> Deref for ReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

/// This `Deref` trait allows a thread to use T from a WriteGuard.
/// This allows us to dereference an immutable reference.
impl<T: ?Sized + Default + Sync> Deref for WriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

/// This `DerefMut` trait allow a thread to use T from a WriteGuard.
/// This allows us to dereference a mutable reference.
impl<T: ?Sized + Default + Sync> DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

/// This `Drop` trait implements the unlock logic for a reader lock. Once the `ReadGuard`
/// goes out of scope, the corresponding read lock is marked as released.
impl<T: ?Sized + Default + Sync> Drop for ReadGuard<'_, T> {
    fn drop(&mut self) {
        unsafe {
            let tid = self.tid;
            self.lock.read_unlock(tid);
        }
    }
}

/// This `Drop` trait implements the unlock logic for a writer lock. Once the `WriteGuard`
/// goes out of scope, the corresponding write lock is marked as released.
impl<T: ?Sized + Default + Sync> Drop for WriteGuard<'_, T> {
    fn drop(&mut self) {
        unsafe {
            self.lock.write_unlock();
        }
    }
}
