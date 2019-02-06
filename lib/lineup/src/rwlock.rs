use crate::{ds, SchedControl, Scheduler, ThreadId, ENV};
use core::cell::UnsafeCell;
use either::{Either, Left, Right};

#[derive(Debug, Clone, Copy)]
enum RwLockIntent {
    Read,
    Write,
}

#[derive(Debug)]
struct RwLock {
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

    pub fn enter(&self, flags: RwLockIntent, yielder: &mut SchedControl) {
        let rw = unsafe { &mut *self.inner.get() };
        rw.enter(flags, yielder)
    }

    pub fn try_enter(&self, flags: RwLockIntent) -> bool {
        let rw = unsafe { &mut *self.inner.get() };
        rw.try_enter(flags)
    }

    pub fn try_upgrade(&self) -> bool {
        let rw = unsafe { &mut *self.inner.get() };
        rw.try_upgrade()
    }

    pub fn downgrade(&self, yielder: &mut SchedControl) {
        let rw = unsafe { &mut *self.inner.get() };
        rw.downgrade(yielder)
    }

    pub fn exit(&self, yielder: &mut SchedControl) {
        let rw = unsafe { &mut *self.inner.get() };
        rw.exit(yielder)
    }

    pub fn held(&self, flags: RwLockIntent) -> bool {
        let rw = unsafe { &*self.inner.get() };
        rw.held(flags)
    }
}

#[derive(Debug)]
struct RwLockInner {
    owner: Option<Either<ThreadId, usize>>,
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
        let tid = unsafe { ENV.current_tid().expect("Can't enter without tid") };
        match (opt, self.owner) {
            (_, None) => false,
            (RwLockIntent::Read, Some(Left(_))) => false,
            (RwLockIntent::Write, Some(Right(_))) => false,
            // This is a bit weird, but apparently as long as we have readers,
            // we assume held() -> true
            (RwLockIntent::Read, Some(Right(_readers))) => true,
            (RwLockIntent::Write, Some(Left(owner))) => tid == owner,
        }
    }

    pub fn enter(&mut self, opt: RwLockIntent, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid().expect("Can't enter without tid") };

        let mut rid: u64 = 0;
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
        let tid = unsafe { ENV.current_tid().expect("Can't enter without tid") };

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
                self.owner = Some(Left(tid));
                true
            }
        }
    }

    // Wake-up strategy prioritize writers over readers to avoid starvations of writes.
    fn wakeup_writer_then_readers(&mut self, tid: ThreadId, yielder: &mut SchedControl) {
        if self.wait_for_write.len() > 0 {
            self.owner = Some(Left(tid));
            yielder.make_runnable(tid);
        } else if self.wait_for_read.len() > 0 {
            self.owner = Some(Right(self.wait_for_read.len()));
            let wait_for_read = self.wait_for_read.clone();
            self.wait_for_read.clear();
            yielder.make_all_runnable(wait_for_read);
        }
    }

    pub fn exit(&mut self, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid().expect("Can't enter without tid") };

        match self.owner {
            Some(Left(_owner)) => {
                self.owner = None;
                self.wakeup_writer_then_readers(tid, yielder);
            }
            Some(Right(reader_count)) => {
                if reader_count > 1 {
                    self.owner = Some(Right(reader_count - 1));
                } else {
                    self.owner = None;
                    self.wakeup_writer_then_readers(tid, yielder);
                }
            }
            None => {
                unreachable!("Can't exit lock that we don't hold!");
            }
        }
    }

    pub fn downgrade(&mut self, yielder: &mut SchedControl) {
        let tid = unsafe { ENV.current_tid().expect("Need tid set.") };

        let owner = self.owner.unwrap().left();
        assert_eq!(owner, Some(tid), "Need to own the lock!");

        self.owner = Some(Right(self.wait_for_read.len() + 1));
        if self.wait_for_read.len() > 0 {
            let wait_for_read = self.wait_for_read.clone();
            self.wait_for_read.clear();
            yielder.make_all_runnable(wait_for_read);
        }
    }

    pub fn try_upgrade(&mut self) -> bool {
        let tid = unsafe { ENV.current_tid().expect("Need tid set.") };

        let can_upgrade = match self.owner {
            Some(Right(reader_count)) => reader_count == 1, // TODO: This assume we're the reader...
            _ => false,
        };

        if can_upgrade {
            self.owner = Some(Left(tid));
            true
        } else {
            false
        }
    }
}

#[test]
fn test_rwlock() {
    use crate::DEFAULT_UPCALLS;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);
    let rwlock = ds::Arc::new(RwLock::new());

    let rwlock1: ds::Arc<RwLock> = rwlock.clone();
    let rwlock2: ds::Arc<RwLock> = rwlock.clone();

    s.spawn(4096, move |mut yielder| {
        for _i in 0..5 {
            rwlock1.enter(RwLockIntent::Read, &mut yielder);
            assert!(!rwlock1.try_upgrade());
        }
    });

    s.spawn(4096, move |mut yielder| {
        for i in 0..5 {
            rwlock2.enter(RwLockIntent::Read, &mut yielder);
            if i == 0 {
                assert!(rwlock2.try_upgrade());
                rwlock2.downgrade(&mut yielder);
            } else {
                assert!(!rwlock2.try_upgrade());
            }
        }
    });

    for _i in 0..10 {
        s.run();
    }
}
