// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2010-2011 Dmitry Vyukov. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

// http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
// This queue is copy pasted from old rust stdlib.

#![allow(warnings)] // For now...

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use fallible_collections::vec::FallibleVec;
use fallible_collections::vec::TryCollect;

use crate::error::KError;
use crate::prelude::*;

struct Node<T> {
    sequence: AtomicUsize,
    value: Option<T>,
}

unsafe impl<T: Send> Send for Node<T> {}
unsafe impl<T: Sync> Sync for Node<T> {}

struct State<T> {
    buffer: CachePadded<Vec<UnsafeCell<Node<T>>>>,
    mask: usize,
    enqueue_pos: CachePadded<AtomicUsize>,
    dequeue_pos: CachePadded<AtomicUsize>,
}

unsafe impl<T: Send> Send for State<T> {}
unsafe impl<T: Sync> Sync for State<T> {}

pub(crate) struct Queue<T> {
    state: Arc<State<T>>,
}

impl<T: Send> State<T> {
    fn with_capacity(capacity: usize) -> Result<State<T>, KError> {
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
            .try_collect::<Vec<_>>()?;

        Ok(State {
            buffer: CachePadded::new(buffer),
            mask: capacity - 1,
            enqueue_pos: CachePadded::new(AtomicUsize::new(0)),
            dequeue_pos: CachePadded::new(AtomicUsize::new(0)),
        })
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
    pub(crate) fn with_capacity(capacity: usize) -> Result<Queue<T>, KError> {
        Ok(Queue {
            state: Arc::try_new(State::with_capacity(capacity)?)?,
        })
    }

    pub(crate) fn push(&self, value: T) -> Result<(), T> {
        self.state.push(value)
    }

    pub(crate) fn pop(&self) -> Option<T> {
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
