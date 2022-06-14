// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2019-2020 Jason Longshore
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Original Source: https://github.com/longshorej/conqueue (MIT License)
// Adjusted to work with no-std, removed tests

#![allow(unused)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};
use core::{mem, ptr};

struct QueueHead<T> {
    element: Option<T>,
    next: *mut QueueHead<T>,
}

/// A `QueueSender` is used to push items into
/// the queue.
///
/// It implements `Send` and `Sync`, thus allowing
/// multiple callers to concurrent push items.
pub struct QueueSender<T> {
    in_queue: Arc<AtomicPtr<QueueHead<T>>>,
}

impl<T> QueueSender<T> {
    /// Push the supplied element into the queue.
    pub fn push(&self, element: T) {
        let mut in_queue = ptr::null_mut();
        let mut new = Box::into_raw(Box::new(QueueHead {
            element: Some(element),
            next: in_queue,
        }));

        loop {
            match self
                .in_queue
                .compare_exchange(in_queue, new, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    return;
                }

                Err(actual) => {
                    in_queue = actual;

                    unsafe {
                        if !in_queue.is_null() && (*in_queue).element.is_none() {
                            Box::from_raw(new);
                            return;
                        }

                        (*new).next = in_queue;
                    }
                }
            }
        }
    }
}

impl<T> Clone for QueueSender<T> {
    fn clone(&self) -> Self {
        Self {
            in_queue: self.in_queue.clone(),
        }
    }
}

impl<T> Drop for QueueSender<T> {
    fn drop(&mut self) {
        let mut in_queue = Arc::new(AtomicPtr::default());

        mem::swap(&mut in_queue, &mut self.in_queue);

        if let Ok(head) = Arc::try_unwrap(in_queue) {
            let head = head.swap(ptr::null_mut(), Ordering::SeqCst);

            if !head.is_null() {
                unsafe { Box::from_raw(head) };
            }
        }
    }
}

unsafe impl<T> Sync for QueueSender<T> {}

unsafe impl<T> Send for QueueSender<T> {}

/// A `QueueReceiver` is used to pop previously
/// pushed items from the queue.
pub struct QueueReceiver<T> {
    in_queue: Arc<AtomicPtr<QueueHead<T>>>,
    out_queue: *mut QueueHead<T>,
}

impl<T> QueueReceiver<T> {
    /// Pop an item from the queue. If the queue is
    /// empty, `None` is returned.
    pub fn pop(&mut self) -> Option<T> {
        if self.out_queue.is_null() {
            let mut head = ptr::null_mut();

            loop {
                match self.in_queue.compare_exchange(
                    head,
                    ptr::null_mut(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => {
                        while !head.is_null() {
                            unsafe {
                                let next = (*head).next;
                                (*head).next = self.out_queue;
                                self.out_queue = head;
                                head = next;
                            }
                        }

                        break;
                    }

                    Err(actual) => {
                        head = actual;

                        if head.is_null() {
                            break;
                        }
                    }
                }
            }
        }

        if self.out_queue.is_null() {
            None
        } else {
            unsafe {
                let head = Box::from_raw(self.out_queue);
                self.out_queue = head.next;
                Some(head.element.unwrap())
            }
        }
    }
}

impl<T> Drop for QueueReceiver<T> {
    fn drop(&mut self) {
        let last = Box::into_raw(Box::new(QueueHead {
            element: None,
            next: ptr::null_mut(),
        }));

        let mut head = ptr::null_mut();

        loop {
            match self
                .in_queue
                .compare_exchange(head, last, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    while !head.is_null() {
                        let boxed = unsafe { Box::from_raw(head) };

                        head = boxed.next;
                    }

                    break;
                }

                Err(actual) => {
                    head = actual;
                }
            }
        }

        let mut in_queue = Arc::new(AtomicPtr::default());

        mem::swap(&mut in_queue, &mut self.in_queue);

        if let Ok(head) = Arc::try_unwrap(in_queue) {
            let head = head.swap(ptr::null_mut(), Ordering::SeqCst);

            if !head.is_null() {
                unsafe { Box::from_raw(head) };
            }
        }
    }
}

unsafe impl<T> Send for QueueReceiver<T> {}
unsafe impl<T> Sync for QueueReceiver<T> {}

pub struct Queue;

impl Queue {
    /// Create a new queue, returning a sender
    /// and receiver pair.
    ///
    /// Senders may be cloned to allow multiple
    /// producers, but only a single receiver
    /// may exist.
    pub fn unbounded<T>() -> (QueueSender<T>, QueueReceiver<T>) {
        let in_queue = Arc::new(AtomicPtr::new(ptr::null_mut()));

        let receiver = QueueReceiver {
            in_queue: in_queue.clone(),
            out_queue: ptr::null_mut(),
        };

        let sender = QueueSender { in_queue };

        (sender, receiver)
    }
}
