// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2010-2011 Dmitry Vyukov. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

// http://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
// This queue is copy pasted from old rust stdlib.

use alloc::alloc::{alloc, Layout};
use alloc::sync::Arc;
use core::alloc::Allocator;
use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use core::slice::from_raw_parts_mut;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicUsize, Ordering};

const DEFAULT_QUEUE_SIZE: usize = 32;
pub const QUEUE_ENTRY_SIZE: usize = 8192;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
pub enum QueueError {
    AllocError,
    NoData,
}

#[repr(C)]
struct Node {
    sequence: AtomicUsize,
    data_len: u16,
    value: [u8; QUEUE_ENTRY_SIZE],
}

unsafe impl Send for Node {}
unsafe impl Sync for Node {}

#[repr(C)]
struct State<'a> {
    mask: usize,
    enqueue_pos: *const AtomicUsize,
    dequeue_pos: *const AtomicUsize,
    buffer: &'a [UnsafeCell<Node>],
}

unsafe impl<'a> Send for State<'a> {}
unsafe impl<'a> Sync for State<'a> {}

impl<'a> State<'a> {
    fn with_capacity(capacity: usize) -> Result<Arc<State<'a>>, QueueError> {
        let (num, buf_size) = Self::capacity(capacity);
        let mem = unsafe {
            alloc(
                match Layout::from_size_align(buf_size, align_of::<State>()) {
                    Ok(layout) => layout,
                    Err(_) => return Err(QueueError::AllocError),
                },
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
    ) -> Result<Arc<State<'a>>, QueueError> {
        let (num, buf_size) = Self::capacity(capacity);
        let mem = alloc
            .allocate(
                match Layout::from_size_align(buf_size, align_of::<State>()) {
                    Ok(layout) => layout,
                    Err(_) => return Err(QueueError::AllocError),
                },
            )
            .expect("Failed to allocate memory for the Queue!");
        let mem = mem.as_ptr() as *mut u8;

        Self::init(init, num, mem)
    }

    fn init(init: bool, num: usize, mem: *mut u8) -> Result<Arc<State<'a>>, QueueError> {
        let state = State {
            mask: num - 1,
            enqueue_pos: unsafe { &mut *(mem as *mut AtomicUsize) },
            dequeue_pos: unsafe {
                &mut *((mem as *mut u8).add(size_of::<AtomicUsize>()) as *mut AtomicUsize)
            },
            buffer: unsafe {
                from_raw_parts_mut(
                    (mem as *mut u8).add(size_of::<AtomicUsize>() * 2) as *mut UnsafeCell<Node>,
                    num,
                )
            },
        };

        if init {
            let buffer = unsafe {
                let ptr =
                    (mem as *mut u8).add(size_of::<AtomicUsize>() * 2) as *mut UnsafeCell<Node>;
                from_raw_parts_mut(ptr, num)
            };

            unsafe {
                for (i, e) in buffer.iter_mut().enumerate() {
                    ::core::ptr::write(
                        e,
                        UnsafeCell::new(Node {
                            sequence: AtomicUsize::new(i),
                            data_len: 0,
                            value: [0u8; QUEUE_ENTRY_SIZE],
                        }),
                    );
                }
                (*state.dequeue_pos).store(0, Release);
                (*state.enqueue_pos).store(0, Release);
            }
        }

        Ok(Arc::new(state))
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
            2 * size_of::<AtomicUsize>() + num * size_of::<UnsafeCell<Node>>(),
        )
    }

    #[inline(always)]
    fn enqueue_pos(&self, ordering: Ordering) -> usize {
        unsafe { (*self.enqueue_pos).load(ordering) }
    }

    #[inline(always)]
    fn dequeue_pos(&self, ordering: Ordering) -> usize {
        unsafe { (*self.dequeue_pos).load(ordering) }
    }

    unsafe fn push(&self, values: &[&[u8]]) -> bool {
        // Calculate and check total data to push
        let push_data_len = values.iter().fold(0, |acc, x| acc + x.len());
        assert!(push_data_len <= QUEUE_ENTRY_SIZE);
        log::debug!("Attempt to push {:?} bytes", push_data_len);

        if push_data_len == 0 {
            return true;
        }

        let mask = self.mask;
        let mut pos = self.enqueue_pos(Relaxed);
        loop {
            let node = &self.buffer[pos & mask];
            let seq = (*node.get()).sequence.load(Acquire);
            let diff: isize = seq as isize - pos as isize;

            match diff {
                0 => {
                    match (*self.enqueue_pos).compare_exchange_weak(pos, pos + 1, Relaxed, Relaxed)
                    {
                        Ok(enqueue_pos) => {
                            debug_assert_eq!(enqueue_pos, pos);
                            (*node.get()).data_len = push_data_len as u16;

                            // Copy each value into the queue
                            let mut offset = 0;
                            for d in values.iter() {
                                (*node.get()).value[offset..offset + d.len()].copy_from_slice(d);
                                offset += d.len();
                            }

                            (*node.get()).sequence.store(pos + 1, Release);
                            break;
                        }
                        Err(enqueue_pos) => pos = enqueue_pos,
                    }
                }
                n if n < 0 => return false,
                _ => pos = self.enqueue_pos(Relaxed),
            }
        }
        true
    }

    unsafe fn pop(&self, values: &mut [&mut [u8]]) -> Result<usize, QueueError> {
        // Calculate maximum total data to receive
        let pop_data_len = values.iter().fold(0, |acc, x| acc + x.len());
        if pop_data_len == 0 {
            return Ok(0);
        }

        let mask = self.mask;
        let mut pos = self.dequeue_pos(Relaxed);
        loop {
            let node = &self.buffer[pos & mask];
            let seq = (*node.get()).sequence.load(Acquire);
            let diff: isize = seq as isize - (pos + 1) as isize;
            match diff {
                0 => {
                    match (*self.dequeue_pos).compare_exchange_weak(pos, pos + 1, Relaxed, Relaxed)
                    {
                        Ok(dequeue_pos) => {
                            debug_assert_eq!(dequeue_pos, pos);
                            let data_len = usize::from((*node.get()).data_len);
                            log::debug!(
                                "Attempt to pop into {:?} bytes, found {:?} bytes",
                                pop_data_len,
                                data_len
                            );
                            assert!(data_len <= pop_data_len);

                            let mut value_index = 0;
                            let mut offset = 0;
                            let mut total_offset = 0;
                            while total_offset < data_len {
                                let data_to_copy = core::cmp::min(
                                    values[value_index].len(), // size of current value
                                    data_len - total_offset,   // data left
                                );
                                values[value_index][offset..offset + data_to_copy].copy_from_slice(
                                    &(*node.get()).value[total_offset..total_offset + data_to_copy],
                                );

                                // Update
                                total_offset += data_to_copy;
                                offset += data_to_copy;

                                // Move to next value if current is full
                                if offset == values[value_index].len() {
                                    offset = 0;
                                    value_index += 1;
                                }
                            }

                            (*node.get()).sequence.store(pos + mask + 1, Release);
                            return Ok(data_len);
                        }
                        Err(dequeue_pos) => pos = dequeue_pos,
                    }
                }
                n if n < 0 => return Err(QueueError::NoData),
                _ => pos = self.dequeue_pos(Relaxed),
            }
        }
    }

    #[inline(always)]
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
pub struct Queue<'a> {
    state: Arc<State<'a>>,
}

impl<'a> Queue<'a> {
    pub fn new() -> Result<Queue<'a>, QueueError> {
        State::with_capacity(DEFAULT_QUEUE_SIZE).map(|state| Queue { state })
    }

    pub fn with_capacity(capacity: usize) -> Result<Queue<'a>, QueueError> {
        Ok(Queue {
            state: State::with_capacity(capacity)?,
        })
    }

    pub fn with_capacity_in<A: Allocator>(
        init: bool,
        capacity: usize,
        alloc: A,
    ) -> Result<Queue<'a>, QueueError> {
        Ok(Queue {
            state: State::with_capacity_in(init, capacity, alloc)?,
        })
    }

    #[inline(always)]
    pub fn enqueue(&self, values: &[&[u8]]) -> bool {
        unsafe { self.state.push(values) }
    }

    #[inline(always)]
    pub fn dequeue(&self, values: &mut [&mut [u8]]) -> Result<usize, QueueError> {
        unsafe { self.state.pop(values) }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { self.state.len() }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        unsafe { self.state.len() == 0 }
    }
}

impl<'a> Clone for Queue<'a> {
    fn clone(&self) -> Queue<'a> {
        Queue {
            state: self.state.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::alloc::Global;
    use alloc::vec;
    use core::sync::atomic::Ordering;
    use std::sync::mpsc::channel;
    use std::thread;

    #[test]
    fn test_default_initialization() {
        let queue = Queue::new().unwrap();
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.state.enqueue_pos(Ordering::Relaxed), 0);
        assert_eq!(queue.state.dequeue_pos(Ordering::Relaxed), 0);
        for i in 0..DEFAULT_QUEUE_SIZE {
            let ele = unsafe { &*queue.state.buffer[i].get() };
            assert!(ele.value.iter().all(|&x| x == 0));
            assert!(ele.sequence.load(Ordering::Relaxed) == i);
        }
    }

    #[test]
    fn test_enqueue() {
        let queue = Queue::new().unwrap();
        assert_eq!(queue.enqueue(&[&[1u8]]), true);
        assert_eq!(queue.state.enqueue_pos(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dequeue() {
        let queue = Queue::new().unwrap();
        assert!(queue.enqueue(&[&[1u8]]));
        assert_eq!(queue.state.enqueue_pos(Ordering::Relaxed), 1);
        assert_eq!(queue.state.dequeue_pos(Ordering::Relaxed), 0);

        let mut entry = [0u8; 1];
        assert_eq!(queue.dequeue(&mut [&mut entry]), Ok(1));
        assert_eq!(entry[0], 1);
        assert_eq!(queue.state.enqueue_pos(Ordering::Relaxed), 1);
        assert_eq!(queue.state.dequeue_pos(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_enqueue_full() {
        let queue = Queue::new().unwrap();
        for i in 0..DEFAULT_QUEUE_SIZE {
            assert_eq!(queue.enqueue(&[&i.to_be_bytes()]), true);
        }
        assert!(queue.state.dequeue_pos(Ordering::Relaxed) == 0);
        assert!(queue.state.enqueue_pos(Ordering::Relaxed) == DEFAULT_QUEUE_SIZE);
        assert_eq!(queue.enqueue(&[&DEFAULT_QUEUE_SIZE.to_be_bytes()]), false);
    }

    #[test]
    fn test_dequeue_empty() {
        let queue = Queue::new().unwrap();
        let mut entry = [0];
        assert!(queue.dequeue(&mut [&mut entry]).is_err());
    }

    #[test]
    fn test_two_clients() {
        let queue = Queue::new().unwrap();
        let producer = queue.clone();
        let consumer = queue.clone();

        assert!(producer.enqueue(&[&[1u8]]));
        assert_eq!(producer.state.enqueue_pos(Ordering::Relaxed), 1);
        assert_eq!(producer.state.dequeue_pos(Ordering::Relaxed), 0);

        let mut entry = [0];
        assert_eq!(consumer.dequeue(&mut [&mut entry]), Ok(1));
        assert_eq!(entry[0], 1);
        assert_eq!(consumer.state.enqueue_pos(Ordering::Relaxed), 1);
        assert_eq!(consumer.state.dequeue_pos(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_parallel_client() {
        let queue = Queue::new().unwrap();
        let producer = queue.clone();
        let consumer = queue.clone();
        let num_iterations = 10 * DEFAULT_QUEUE_SIZE;

        let producer_thread = std::thread::spawn(move || {
            for i in 0..num_iterations {
                loop {
                    if producer.enqueue(&[&(i as i32).to_be_bytes()]) {
                        break;
                    }
                }
            }
        });

        let consumer_thread = std::thread::spawn(move || {
            let mut entry = [0u8; 4];
            for i in 0..num_iterations {
                loop {
                    if consumer.dequeue(&mut [&mut entry]).is_ok() {
                        assert_eq!(i32::from_be_bytes(entry), i as i32);
                        break;
                    }
                }
            }
        });

        producer_thread.join().unwrap();
        consumer_thread.join().unwrap();
    }

    #[test]
    fn len() {
        // fill and drain N elements from the queue, with N: 1..=1024
        let q = Queue::with_capacity(1024).unwrap();
        let mut entry = [0u8; 4];
        assert_eq!(q.len(), 0);
        for i in 1..=1024 {
            for j in 0..i {
                assert_eq!(q.len(), j);
                let _ = q.enqueue(&[&(j as i32).to_be_bytes()]);
                assert_eq!(q.len(), j + 1);
            }
            for j in (0..i).rev() {
                assert_eq!(q.len(), j + 1);
                let _ = q.dequeue(&mut [&mut entry]);
                assert_eq!(q.len(), j);
            }
        }

        // steps through each potential wrap-around by filling to N - 1 and
        // draining each time
        let q = Queue::with_capacity(1024).unwrap();
        assert_eq!(q.len(), 0);
        for _ in 1..=1024 {
            for j in 0..1023 {
                assert_eq!(q.len(), j);
                let _ = q.enqueue(&[&(j as i32).to_be_bytes()]);
                assert_eq!(q.len(), j + 1);
            }
            for j in (0..1023).rev() {
                assert_eq!(q.len(), j + 1);
                let _ = q.dequeue(&mut [&mut entry]);
                assert_eq!(q.len(), j);
            }
        }
    }

    #[test]
    fn test() {
        let nthreads = 8;
        let nmsgs = 1000;
        let mut entry = [0u8; 4];
        let q = Queue::with_capacity(nthreads * nmsgs).unwrap();
        assert!(q.dequeue(&mut [&mut entry]).is_err());
        let (tx, rx) = channel();

        for _ in 0..nthreads {
            let q = q.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                let q = q;
                for i in 0..nmsgs {
                    assert!(q.enqueue(&[&(i as i32).to_be_bytes()]));
                }
                tx.send(()).unwrap();
            });
        }

        let mut completion_rxs = vec![];
        for _ in 0..nthreads {
            let (tx, rx) = channel();
            completion_rxs.push(rx);
            let q = q.clone();
            thread::spawn(move || {
                let q = q;
                let mut i = 0;
                loop {
                    match q.dequeue(&mut [&mut entry]) {
                        Err(_) => {}
                        Ok(_) => {
                            i += 1;
                            if i == nmsgs {
                                break;
                            }
                        }
                    }
                }
                tx.send(i).unwrap();
            });
        }

        for rx in completion_rxs.iter_mut() {
            assert_eq!(nmsgs, rx.recv().unwrap());
        }
        for _ in 0..nthreads {
            rx.recv().unwrap();
        }
    }

    #[test]
    fn test_custom_allocator() {
        let q = Queue::with_capacity_in(true, DEFAULT_QUEUE_SIZE, Global).unwrap();
        assert_eq!(q.len(), 0);
        assert_eq!(q.state.enqueue_pos(Ordering::Relaxed), 0);
        assert_eq!(q.state.dequeue_pos(Ordering::Relaxed), 0);
        for i in 0..DEFAULT_QUEUE_SIZE {
            let ele = unsafe { &*q.state.buffer[i].get() };
            assert!(ele.value.iter().all(|&x| x == 0));
            assert!(ele.sequence.load(Ordering::Relaxed) == i);
        }
    }
}
