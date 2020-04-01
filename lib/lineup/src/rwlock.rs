use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_utils::CachePadded;

use crate::mutex::Mutex;

use log::trace;

#[derive(Debug, Clone, Copy)]
pub enum RwLockIntent {
    Read,
    Write,
}

#[derive(Debug)]
pub struct RwLock {
    inner: UnsafeCell<RwLockInner>,
}

unsafe impl Send for RwLock {}
unsafe impl Sync for RwLock {}

impl RwLock {
    pub fn new() -> RwLock {
        RwLock {
            inner: UnsafeCell::new(RwLockInner::new()),
        }
    }

    pub fn enter(&self, flags: RwLockIntent) {
        let rw = unsafe { &mut *self.inner.get() };
        rw.enter(flags)
    }

    pub fn try_enter(&self, flags: RwLockIntent) -> bool {
        let rw = unsafe { &mut *self.inner.get() };
        rw.try_enter(flags)
    }

    pub fn try_upgrade(&self) -> bool {
        let rw = unsafe { &mut *self.inner.get() };
        rw.try_upgrade()
    }

    pub fn downgrade(&self) {
        let rw = unsafe { &mut *self.inner.get() };
        rw.downgrade()
    }

    pub fn exit(&self) {
        let rw = unsafe { &mut *self.inner.get() };
        rw.exit()
    }

    pub fn held(&self, flags: RwLockIntent) -> bool {
        let rw = unsafe { &*self.inner.get() };
        rw.held(flags)
    }
}

/// Holds the current status of the reader-writer lock.
#[repr(usize)]
enum RwLockStatus {
    /// Lock not in use.
    Free = 0,
    /// Locked as writeable.
    Writeable = 1,
    /// Locked as readable.
    Readable = 2,
}

#[derive(Debug)]
struct RwLockInner {
    access: Mutex,
    wait: Mutex,
    readers: CachePadded<AtomicUsize>,
    lock_type: CachePadded<AtomicUsize>,
}

impl RwLockInner {
    pub fn new() -> RwLockInner {
        RwLockInner {
            access: Mutex::new(false, true),
            wait: Mutex::new(false, true),
            readers: CachePadded::new(AtomicUsize::new(0)),
            lock_type: CachePadded::new(AtomicUsize::new(RwLockStatus::Free as usize)),
        }
    }

    pub fn held(&self, opt: RwLockIntent) -> bool {
        let held = match opt {
            RwLockIntent::Read => {
                self.lock_type.load(Ordering::SeqCst) == RwLockStatus::Readable as usize
            }
            RwLockIntent::Write => {
                self.lock_type.load(Ordering::SeqCst) == RwLockStatus::Writeable as usize
            }
        };

        trace!("holding rwlock with opt {:?}: {}", opt, held);
        held
    }

    pub fn enter(&self, opt: RwLockIntent) {
        self.wait.enter();

        match opt {
            RwLockIntent::Write => {
                // Get access and set the lock type
                self.access.enter();
                self.lock_type
                    .store(RwLockStatus::Writeable as usize, Ordering::SeqCst);
            }
            RwLockIntent::Read => {
                // We are the first reader, get access and set lock type
                if self.readers.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.access.enter();
                    self.lock_type
                        .store(RwLockStatus::Readable as usize, Ordering::SeqCst);
                }
                // else: Someone already has the read-lock, just increasing readers is fine
            }
        }

        self.wait.exit();
    }

    pub fn try_enter(&self, opt: RwLockIntent) -> bool {
        if self.wait.try_enter() {
            match opt {
                RwLockIntent::Write => {
                    if self.access.try_enter() {
                        // Acquired lock, change to writeable
                        self.lock_type
                            .store(RwLockStatus::Writeable as usize, Ordering::SeqCst);
                        self.wait.exit();
                        true
                    } else {
                        // Already locked (either read or write)
                        self.wait.exit();
                        false
                    }
                }
                RwLockIntent::Read => {
                    // want to be a reader?
                    // If you're the first need to get the access mutex & increment readers
                    // else need to just increment readers
                    let mut readers = self.readers.load(Ordering::SeqCst);
                    loop {
                        // Are we the first reader?
                        if readers == 0 {
                            if self.access.try_enter() {
                                // Managed to gain access to the RwLock
                                self.readers.store(1, Ordering::SeqCst);
                                self.lock_type
                                    .store(RwLockStatus::Readable as usize, Ordering::SeqCst);
                                self.wait.exit();
                                return true;
                            } else {
                                // Probably locked as writeable
                                self.wait.exit();
                                return false;
                            }
                        }

                        match self.readers.compare_exchange(
                            readers,
                            readers + 1,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(_previous) => {
                                // Successfully increased reader
                                self.wait.exit();
                                return true;
                            }
                            Err(previous) => {
                                // Couldn't increase readers try again with new value
                                readers = previous;
                                continue;
                            }
                        }
                    }
                }
            }
        } else {
            // Someone is inside this RwLock at the moment
            return false;
        }
    }

    pub fn exit(&self) {
        if self.lock_type.load(Ordering::SeqCst) == RwLockStatus::Writeable as usize
            || self.readers.fetch_sub(1, Ordering::SeqCst) == 1
        {
            // Writer or last reader is leaving
            self.lock_type
                .store(RwLockStatus::Free as usize, Ordering::SeqCst);
            self.access.exit();
        } else {
            // A reader is leaving but we still have more readers
        }
    }

    pub fn downgrade(&self) {
        self.lock_type
            .store(RwLockStatus::Readable as usize, Ordering::SeqCst);
        if self.readers.fetch_add(1, Ordering::SeqCst) != 0 {
            // If we're going from writer -> reader but we're not the first reader
            // (race with enter) we should give up the lock so 1st reader can acquire it
            self.access.exit();
        }
    }

    pub fn try_upgrade(&self) -> bool {
        let assumed_readers = 1;
        match self
            .readers
            .compare_exchange(assumed_readers, 0, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_previous) => {
                // We are the only reader
                self.lock_type
                    .store(RwLockStatus::Writeable as usize, Ordering::SeqCst);
                true
            }
            Err(_previous) => {
                // There are other readers
                false
            }
        }
    }
}

#[test]
fn test_rwlock() {
    let _r = env_logger::try_init();

    use crate::{DEFAULT_THREAD_SIZE, DEFAULT_UPCALLS};
    use core::ptr;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);

    let rwlock = ds::Arc::new(RwLock::new());
    let rwlock1: ds::Arc<RwLock> = rwlock.clone();
    let rwlock2: ds::Arc<RwLock> = rwlock.clone();

    s.spawn(
        DEFAULT_THREAD_SIZE,
        move |_| {
            rwlock2.enter(RwLockIntent::Read);
            Environment::thread().relinquish();

            assert!(rwlock2.held(RwLockIntent::Read));
            assert!(!rwlock2.held(RwLockIntent::Write));

            assert!(rwlock2.try_upgrade());

            assert!(!rwlock2.held(RwLockIntent::Read));
            assert!(rwlock2.held(RwLockIntent::Write));

            rwlock2.exit();
        },
        ptr::null_mut(),
    );

    s.spawn(
        DEFAULT_THREAD_SIZE,
        move |_| {
            for _i in 0..5 {
                rwlock1.enter(RwLockIntent::Read);
                assert!(rwlock1.held(RwLockIntent::Read));
                assert!(!rwlock1.held(RwLockIntent::Write));
                assert!(!rwlock1.try_upgrade());
                rwlock1.exit();
            }
        },
        ptr::null_mut(),
    );

    s.run();
}
