use core::cell::UnsafeCell;
use either::{Either, Left, Right};

use crate::tls::Environment;
use crate::{ds, Scheduler, ThreadId, ThreadState};
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

#[derive(Debug)]
struct RwLockInner {
    owner: Option<Either<*const u64, usize>>,
    wait_for_read: ds::Vec<ThreadId>,
    wait_for_write: ds::Vec<ThreadId>,
}

impl RwLockInner {
    pub fn new() -> RwLockInner {
        RwLockInner {
            owner: None,
            wait_for_read: ds::Vec::with_capacity(Scheduler::MAX_THREADS),
            wait_for_write: ds::Vec::with_capacity(Scheduler::MAX_THREADS),
        }
    }

    pub fn held(&self, opt: RwLockIntent) -> bool {
        let tid = Environment::tid();
        let thread = Environment::thread();

        let held = match (opt, self.owner) {
            (_, None) => false,
            (RwLockIntent::Read, Some(Left(_))) => false,
            (RwLockIntent::Write, Some(Right(_))) => false,
            // If we have readers and our intent is read, we 'own' the lock
            (RwLockIntent::Read, Some(Right(_readers))) => true,
            (RwLockIntent::Write, Some(Left(owner))) => thread.rump_lwp == owner,
        };

        trace!("holding rwlock with opt {:?}: {}", opt, held);
        held
    }

    pub fn enter(&mut self, opt: RwLockIntent) {
        let tid = Environment::tid();
        let yielder: &mut ThreadState = Environment::thread();

        let mut rid = 0;
        match (self.try_enter(opt), opt) {
            (true, _) => return,
            (false, RwLockIntent::Read) => {
                (yielder.upcalls.deschedule)(&mut rid, None);
                self.wait_for_read.push(tid);
                yielder.make_unrunnable(tid);
                assert!(self.try_enter(opt));
                (yielder.upcalls.schedule)(&rid, None);
            }
            (false, RwLockIntent::Write) => {
                (yielder.upcalls.deschedule)(&mut rid, None);
                self.wait_for_write.push(tid);
                yielder.make_unrunnable(tid);
                assert!(self.try_enter(opt));
                (yielder.upcalls.schedule)(&rid, None);
            }
        }
    }

    pub fn try_enter(&mut self, opt: RwLockIntent) -> bool {
        let tid = Environment::tid();

        match (opt, self.owner) {
            (RwLockIntent::Read, Some(Left(_owner))) => false,
            (RwLockIntent::Write, Some(Left(_owner))) => false,
            (RwLockIntent::Write, Some(Right(_reader_count))) => false,
            (RwLockIntent::Read, Some(Right(reader_count))) => {
                self.owner = Some(Right(reader_count + 1));
                true
            }
            (RwLockIntent::Read, None) => {
                if self.wait_for_write.len() == 0 {
                    self.owner = Some(Right(1));
                    true
                } else {
                    false
                }
            }
            (RwLockIntent::Write, None) => {
                self.owner = Some(Left(Environment::thread().rump_lwp));
                true
            }
        }
    }

    // Wake-up strategy prioritize writers over readers to avoid starvations of writes.
    fn wakeup_writer_then_readers(&mut self, tid: ThreadId) {
        let yielder: &mut ThreadState = Environment::thread();

        if self.wait_for_write.len() > 0 {
            self.owner = Some(Left(yielder.rump_lwp));
            yielder.make_runnable(tid);
        } else if self.wait_for_read.len() > 0 {
            self.owner = Some(Right(self.wait_for_read.len()));
            let wait_for_read = self.wait_for_read.clone();
            self.wait_for_read.clear();
            yielder.make_all_runnable(wait_for_read);
        }
    }

    pub fn exit(&mut self) {
        let tid = Environment::tid();
        trace!(
            "rwlock exit {:?} {:?} {:?}",
            tid,
            self.wait_for_read,
            self.wait_for_write
        );

        match self.owner {
            Some(Left(_owner)) => {
                self.owner = None;
                self.wakeup_writer_then_readers(tid);
            }
            Some(Right(reader_count)) => {
                if reader_count > 1 {
                    self.owner = Some(Right(reader_count - 1));
                } else {
                    self.owner = None;
                    self.wakeup_writer_then_readers(tid);
                }
            }
            None => {
                unreachable!("Can't exit lock that we don't hold!");
            }
        }
    }

    pub fn downgrade(&mut self) {
        let tid = Environment::tid();

        let owner = self.owner.unwrap().left();
        assert_eq!(
            owner,
            Some(Environment::thread().rump_lwp),
            "Need to own the lock!"
        );

        self.owner = Some(Right(self.wait_for_read.len() + 1));
        if self.wait_for_read.len() > 0 {
            let wait_for_read = self.wait_for_read.clone();
            self.wait_for_read.clear();

            let yielder: &mut ThreadState = Environment::thread();
            yielder.make_all_runnable(wait_for_read);
        }
    }

    pub fn try_upgrade(&mut self) -> bool {
        let tid = Environment::tid();

        let can_upgrade = match self.owner {
            Some(Right(reader_count)) => reader_count == 1, // TODO: This assume we're the reader...
            _ => false,
        };

        if can_upgrade {
            trace!("try_upgrade upgrade successful");
            self.owner = Some(Left(Environment::thread().rump_lwp));
            true
        } else {
            trace!("can not upgrade reader_count is {:?}", self.owner);
            false
        }
    }
}

#[test]
fn test_rwlock() {
    use crate::DEFAULT_UPCALLS;
    use core::ptr;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);

    let rwlock = ds::Arc::new(RwLock::new());
    let rwlock1: ds::Arc<RwLock> = rwlock.clone();
    let rwlock2: ds::Arc<RwLock> = rwlock.clone();

    s.spawn(
        32 * 4096,
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
        32 * 4096,
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
