// Copyright (c) 2010-2011 Dmitry Vyukov. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//    1. Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//    2. Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY DMITRY VYUKOV "AS IS" AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT
// SHALL DMITRY VYUKOV OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// The views and conclusions contained in the software and documentation are
// those of the authors and should not be interpreted as representing official
// policies, either expressed or implied, of Dmitry Vyukov.

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
