// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::cell::UnsafeCell;

use crate::condvar::CondVar;
use crate::mutex::Mutex;

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
            count,
            mutex: Mutex::new_kmutex(),
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
        self.count -= self.count;
        self.mutex.exit();
    }
}

#[test]
fn test_semaphore() {
    use alloc::sync::Arc;
    use core::ptr;

    use crate::scheduler::SmpScheduler;
    use crate::stack::DEFAULT_STACK_SIZE_BYTES;
    use crate::tls2::SchedulerControlBlock;

    let s: SmpScheduler = Default::default();

    let cv = Arc::new(Semaphore::new(0));
    let cv1: Arc<Semaphore> = cv.clone();
    let cv2: Arc<Semaphore> = cv.clone();

    s.spawn(
        DEFAULT_STACK_SIZE_BYTES,
        move |_yielder| {
            for _i in 0..5 {
                cv2.down();
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    s.spawn(
        DEFAULT_STACK_SIZE_BYTES,
        move |_yielder| {
            for _i in 0..5 {
                cv1.up();
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    s.run(&scb);
}
