use core::cell::UnsafeCell;
use core::ops::Add;
use core::time::Duration;

use log::trace;
use rawtime::Instant;

use crate::condvar::CondVar;
use crate::mutex::Mutex;

use crate::tls::Environment;
use crate::{ds, Scheduler, ThreadId, ThreadState, YieldRequest};

#[derive(Debug)]
pub struct Semaphore {
    inner: UnsafeCell<SemaphoreInner>,
}

unsafe impl Send for Semaphore {}
unsafe impl Sync for Semaphore {}

impl Semaphore {
    pub fn new(count: isize) -> Semaphore {
        Semaphore {
            inner: UnsafeCell::new(SemaphoreInner::new(count)),
        }
    }

    pub fn up(&self) {
        let sem = unsafe { &mut *self.inner.get() };
        sem.up()
    }

    pub fn down(&self) {
        let sem = unsafe { &mut *self.inner.get() };
        sem.down()
    }
}

#[derive(Debug)]
struct SemaphoreInner {
    count: isize,
    mutex: Mutex,
    cv: CondVar,
}

impl Drop for SemaphoreInner {
    fn drop(&mut self) {}
}

impl SemaphoreInner {
    pub fn new(count: isize) -> SemaphoreInner {
        SemaphoreInner {
            count: count,
            mutex: Mutex::new(false, true),
            cv: CondVar::new(),
        }
    }

    pub fn up(&mut self) {
        self.mutex.enter();
        self.count += 1;
        if self.count > 0 {
            self.cv.signal();
        }
        self.mutex.exit();
    }

    pub fn down(&mut self) {
        self.mutex.enter();
        if self.count <= 0 {
            self.cv.wait(&self.mutex)
        }
        self.count = self.count - 1;
        self.mutex.exit();
    }
}

#[test]
fn test_semaphore() {
    use crate::DEFAULT_UPCALLS;
    use core::ptr;
    let mut s = Scheduler::new(DEFAULT_UPCALLS);

    let cv = ds::Arc::new(Semaphore::new(0));
    let cv1: ds::Arc<Semaphore> = cv.clone();
    let cv2: ds::Arc<Semaphore> = cv.clone();

    s.spawn(
        32 * 4096,
        move |mut yielder| {
            for _i in 0..5 {
                cv2.down();
            }
        },
        ptr::null_mut(),
    );

    s.spawn(
        32 * 4096,
        move |mut yielder| {
            for _i in 0..5 {
                cv1.up();
            }
        },
        ptr::null_mut(),
    );

    s.run();
}
