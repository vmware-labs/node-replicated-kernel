// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2010-2011 Dmitry Vyukov. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

#![allow(warnings)] // For now...

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

// http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
// This queue is copy pasted from old rust stdlib.

struct Node<T> {
    sequence: AtomicUsize,
    value: Option<T>,
}

unsafe impl<T: Send> Send for Node<T> {}
unsafe impl<T: Sync> Sync for Node<T> {}

struct State<T> {
    _pad0: [u8; 64],
    buffer: Vec<UnsafeCell<Node<T>>>,
    mask: usize,
    _pad1: [u8; 64],
    enqueue_pos: AtomicUsize,
    _pad2: [u8; 64],
    dequeue_pos: AtomicUsize,
    _pad3: [u8; 64],
}

unsafe impl<T: Send> Send for State<T> {}
unsafe impl<T: Sync> Sync for State<T> {}

pub struct Queue<T> {
    state: Arc<State<T>>,
}

impl<T: Send> State<T> {
    fn with_capacity(capacity: usize) -> State<T> {
        let capacity = if capacity < 2 || (capacity & (capacity - 1)) != 0 {
            if capacity < 2 {
                2
            } else {
                // use next power of 2 as capacity
                capacity.next_power_of_two()
            }
        } else {
            capacity
        };
        let buffer = (0..capacity)
            .map(|i| {
                UnsafeCell::new(Node {
                    sequence: AtomicUsize::new(i),
                    value: None,
                })
            })
            .collect::<Vec<_>>();
        State {
            _pad0: [0; 64],
            buffer: buffer,
            mask: capacity - 1,
            _pad1: [0; 64],
            enqueue_pos: AtomicUsize::new(0),
            _pad2: [0; 64],
            dequeue_pos: AtomicUsize::new(0),
            _pad3: [0; 64],
        }
    }

    fn push(&self, value: T) -> Result<(), T> {
        let mask = self.mask;
        let mut pos = self.enqueue_pos.load(Relaxed);
        loop {
            let node = &self.buffer[pos & mask];
            let seq = unsafe { (*node.get()).sequence.load(Acquire) };
            let diff: isize = seq as isize - pos as isize;

            if diff == 0 {
                match self
                    .enqueue_pos
                    .compare_exchange_weak(pos, pos + 1, Relaxed, Relaxed)
                {
                    Ok(enqueue_pos) => {
                        debug_assert_eq!(enqueue_pos, pos);
                        unsafe {
                            (*node.get()).value = Some(value);
                            (*node.get()).sequence.store(pos + 1, Release);
                        }
                        break;
                    }
                    Err(enqueue_pos) => pos = enqueue_pos,
                }
            } else if diff < 0 {
                return Err(value);
            } else {
                pos = self.enqueue_pos.load(Relaxed);
            }
        }
        Ok(())
    }

    fn pop(&self) -> Option<T> {
        let mask = self.mask;
        let mut pos = self.dequeue_pos.load(Relaxed);
        loop {
            let node = &self.buffer[pos & mask];
            let seq = unsafe { (*node.get()).sequence.load(Acquire) };
            let diff: isize = seq as isize - (pos + 1) as isize;
            if diff == 0 {
                match self
                    .dequeue_pos
                    .compare_exchange_weak(pos, pos + 1, Relaxed, Relaxed)
                {
                    Ok(dequeue_pos) => {
                        debug_assert_eq!(dequeue_pos, pos);
                        unsafe {
                            let value = (*node.get()).value.take();
                            (*node.get()).sequence.store(pos + mask + 1, Release);
                            return value;
                        }
                    }
                    Err(dequeue_pos) => pos = dequeue_pos,
                }
            } else if diff < 0 {
                return None;
            } else {
                pos = self.dequeue_pos.load(Relaxed);
            }
        }
    }
}

impl<T: Send> Queue<T> {
    pub fn with_capacity(capacity: usize) -> Queue<T> {
        Queue {
            state: Arc::new(State::with_capacity(capacity)),
        }
    }

    pub fn push(&self, value: T) -> Result<(), T> {
        self.state.push(value)
    }

    pub fn pop(&self) -> Option<T> {
        self.state.pop()
    }
}

impl<T: Send> Clone for Queue<T> {
    fn clone(&self) -> Queue<T> {
        Queue {
            state: self.state.clone(),
        }
    }
}
