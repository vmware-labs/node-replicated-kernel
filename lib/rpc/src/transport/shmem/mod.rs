// Shmem Transport
use alloc::alloc::Allocator;

use alloc::sync::Arc;
pub mod allocator;
pub mod transport;

pub mod queue_mpmc;
pub use queue_mpmc::{Queue, QueueError};

#[repr(transparent)]
pub struct Sender<'a>(Arc<Queue<'a>>);

unsafe impl<'a> Send for Sender<'a> {}
unsafe impl<'a> Sync for Sender<'a> {}

impl<'a> Sender<'a> {
    pub fn with_capacity_in<A: Allocator>(capacity: usize, alloc: A) -> Sender<'a> {
        Sender(Arc::new(
            Queue::with_capacity_in(false, capacity, alloc).unwrap(),
        ))
    }

    #[inline(always)]
    pub fn with_shared_queue(q: Arc<Queue<'a>>) -> Sender<'a> {
        Sender(q.clone())
    }

    #[inline(always)]
    pub fn send(&self, data: &[&[u8]]) -> bool {
        while !self.0.enqueue(data) {}
        true
    }

    #[inline(always)]
    pub fn try_send(&self, data: &[&[u8]]) -> bool {
        self.0.enqueue(data)
    }
}

#[repr(transparent)]
pub struct Receiver<'a>(Arc<Queue<'a>>);

unsafe impl<'a> Send for Receiver<'a> {}
unsafe impl<'a> Sync for Receiver<'a> {}

impl<'a> Receiver<'a> {
    pub fn with_capacity_in<A: Allocator>(capacity: usize, alloc: A) -> Receiver<'a> {
        Receiver(Arc::new(
            Queue::with_capacity_in(true, capacity, alloc).unwrap(),
        ))
    }

    #[inline(always)]
    pub fn with_shared_queue(q: Arc<Queue<'a>>) -> Receiver<'a> {
        Receiver(q.clone())
    }

    #[inline(always)]
    pub fn recv(&self, data_out: &mut [&mut [u8]]) -> usize {
        loop {
            let ret = self.0.dequeue(data_out);
            if let Ok(bytes_received) = ret {
                return bytes_received;
            }
        }
    }

    #[inline(always)]
    pub fn try_recv(&self, data_out: &mut [&mut [u8]]) -> Result<usize, QueueError> {
        self.0.dequeue(data_out)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_queue_tests() {
        use super::*;

        let queue = Arc::new(Queue::new().unwrap());
        let sender = Sender::with_shared_queue(queue.clone());
        let receiver = Receiver::with_shared_queue(queue.clone());

        let send_data: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        sender.send(&[&send_data]);

        let mut rx_data = [0u8; 10];
        assert_eq!(receiver.recv(&mut [&mut rx_data]), 10);
        assert_eq!(&send_data, &rx_data[0..send_data.len()]);
    }
}
