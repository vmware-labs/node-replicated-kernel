// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2010-2011 Dmitry Vyukov. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

// http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
// This queue is copy pasted from old rust stdlib.

#![allow(warnings)] // For now...

use alloc::alloc::{alloc, Layout};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Allocator;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::slice::from_raw_parts_mut;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::QUEUE_SIZE;

#[repr(C)]
struct Node<T> {
    sequence: AtomicUsize,
    value: Option<T>,
}

unsafe impl<T: Send> Send for Node<T> {}
unsafe impl<T: Sync> Sync for Node<T> {}

#[repr(C)]
struct State<'a, T> {
    mask: usize,
    enqueue_pos: *const AtomicUsize,
    dequeue_pos: *const AtomicUsize,
    buffer: &'a [UnsafeCell<Node<T>>],
}

unsafe impl<'a, T: Send> Send for State<'a, T> {}
unsafe impl<'a, T: Sync> Sync for State<'a, T> {}

impl<'a, T: Send> State<'a, T> {
    fn with_capacity(capacity: usize) -> Result<Box<State<'a, T>>, ()> {
        let (num, buf_size) = Self::capacity(capacity);
        let mem = unsafe {
            alloc(
                Layout::from_size_align(buf_size, align_of::<State<T>>())
                    .expect("Alignment error while allocating the Queue!"),
            )
        };
        if mem.is_null() {
            panic!("Failed to allocate memory for the Queue!");
        }

        Self::init(true, num, mem)
    }

    fn with_capacity_in<A: Allocator>(
        init: bool,
        capacity: usize,
        alloc: A,
    ) -> Result<Box<State<'a, T>>, ()> {
        let (num, buf_size) = Self::capacity(capacity);
        let mem = unsafe {
            alloc
                .allocate(
                    Layout::from_size_align(buf_size, align_of::<State<T>>())
                        .expect("Alignment error while allocating the Queue!"),
                )
                .expect("Failed to allocate memory for the Queue!")
        };
        let mem = mem.as_ptr() as *mut u8;

        Self::init(init, num, mem)
    }

    fn init(init: bool, num: usize, mem: *mut u8) -> Result<Box<State<'a, T>>, ()> {
        let mut state = State {
            mask: num - 1,
            enqueue_pos: unsafe { &mut *(mem as *mut AtomicUsize) },
            dequeue_pos: unsafe {
                &mut *((mem as *mut u8).add(size_of::<AtomicUsize>()) as *mut AtomicUsize)
            },
            buffer: unsafe {
                from_raw_parts_mut(
                    (mem as *mut u8).add(size_of::<AtomicUsize>() * 2) as *mut UnsafeCell<Node<T>>,
                    num,
                )
            },
        };

        if init {
            let mut buffer = unsafe {
                let ptr =
                    (mem as *mut u8).add(size_of::<AtomicUsize>() * 2) as *mut UnsafeCell<Node<T>>;
                from_raw_parts_mut(ptr, num)
            };

            unsafe {
                for (i, e) in buffer.iter_mut().enumerate() {
                    ::core::ptr::write(
                        e,
                        UnsafeCell::new(Node {
                            sequence: AtomicUsize::new(i),
                            value: None,
                        }),
                    );
                }
                (*state.dequeue_pos).store(0, Release);
                (*state.enqueue_pos).store(0, Release);
            }
        }

        Ok(Box::new(state))
    }

    fn capacity(capacity: usize) -> (usize, usize) {
        let num = if capacity < 2 || (capacity & (capacity - 1)) != 0 {
            if capacity < 2 {
                2
            } else {
                // use next power of 2 as capacity
                capacity.next_power_of_two()
            }
        } else {
            capacity
        };

        (
            num,
            2 * size_of::<AtomicUsize>() + num * size_of::<UnsafeCell<Node<T>>>(),
        )
    }

    fn enqueue_pos(&self, ordering: Ordering) -> usize {
        unsafe { (*self.enqueue_pos).load(ordering) }
    }

    fn dequeue_pos(&self, ordering: Ordering) -> usize {
        unsafe { (*self.dequeue_pos).load(ordering) }
    }

    unsafe fn push(&self, value: T) -> Result<(), T> {
        let mask = self.mask;
        let mut pos = self.enqueue_pos(Relaxed);
        loop {
            let node = &self.buffer[pos & mask];
            let seq = (*node.get()).sequence.load(Acquire);
            let diff: isize = seq as isize - pos as isize;

            if diff == 0 {
                match (*self.enqueue_pos).compare_exchange_weak(pos, pos + 1, Relaxed, Relaxed) {
                    Ok(enqueue_pos) => {
                        debug_assert_eq!(enqueue_pos, pos);
                        (*node.get()).value = Some(value);
                        (*node.get()).sequence.store(pos + 1, Release);
                        break;
                    }
                    Err(enqueue_pos) => pos = enqueue_pos,
                }
            } else if diff < 0 {
                return Err(value);
            } else {
                pos = self.enqueue_pos(Relaxed);
            }
        }
        Ok(())
    }

    unsafe fn pop(&self) -> Option<T> {
        let mask = self.mask;
        let mut pos = self.dequeue_pos(Relaxed);
        loop {
            let node = &self.buffer[pos & mask];
            let seq = (*node.get()).sequence.load(Acquire);
            let diff: isize = seq as isize - (pos + 1) as isize;
            if diff == 0 {
                match (*self.dequeue_pos).compare_exchange_weak(pos, pos + 1, Relaxed, Relaxed) {
                    Ok(dequeue_pos) => {
                        debug_assert_eq!(dequeue_pos, pos);
                        let value = (*node.get()).value.take();
                        (*node.get()).sequence.store(pos + mask + 1, Release);
                        return value;
                    }
                    Err(dequeue_pos) => pos = dequeue_pos,
                }
            } else if diff < 0 {
                return None;
            } else {
                pos = self.dequeue_pos(Relaxed);
            }
        }
    }

    unsafe fn len(&self) -> usize {
        let dequeue = self.dequeue_pos(Relaxed);
        let enqueue = self.enqueue_pos(Relaxed);
        if enqueue > dequeue {
            enqueue - dequeue
        } else {
            dequeue - enqueue
        }
    }
}

// Lock-free MPMC queue.
pub struct Queue<'a, T> {
    state: Arc<Box<State<'a, T>>>,
}

impl<'a, T: Send> Queue<'a, T> {
    pub fn new() -> Result<Queue<'a, T>, ()> {
        State::with_capacity(QUEUE_SIZE).map(|state| Queue {
            state: Arc::new(state),
        })
    }

    pub fn with_capacity(capacity: usize) -> Result<Queue<'a, T>, ()> {
        Ok(Queue {
            state: Arc::new(State::with_capacity(capacity)?),
        })
    }

    pub fn with_capacity_in<A: Allocator>(
        init: bool,
        capacity: usize,
        alloc: A,
    ) -> Result<Queue<'a, T>, ()> {
        Ok(Queue {
            state: Arc::new(State::with_capacity_in(init, capacity, alloc)?),
        })
    }

    pub fn enqueue(&self, value: T) -> Result<(), T> {
        unsafe { self.state.push(value) }
    }

    pub fn dequeue(&self) -> Option<T> {
        unsafe { self.state.pop() }
    }

    pub fn len(&self) -> usize {
        unsafe { self.state.len() }
    }
}

impl<'a, T: Send> Clone for Queue<'a, T> {
    fn clone(&self) -> Queue<'a, T> {
        Queue {
            state: self.state.clone(),
        }
    }
}
