// Shmem Transport
use alloc::alloc::Allocator;

use alloc::sync::Arc;
pub mod allocator;
pub mod transport;

mod queue_mpmc;
pub use queue_mpmc::Queue;

#[repr(transparent)]
pub struct Sender<'a, T>(Arc<Queue<'a, T>>);

unsafe impl<'a, T: Send> Send for Sender<'a, T> {}
unsafe impl<'a, T: Sync> Sync for Sender<'a, T> {}

impl<'a, T: Send + Clone> Sender<'a, T> {
    pub fn with_capacity_in<A: Allocator>(capacity: usize, alloc: A) -> Sender<'a, T> {
        Sender(Arc::new(
            Queue::<T>::with_capacity_in(false, capacity, alloc).unwrap(),
        ))
    }

    pub fn with_shared_queue(q: Arc<Queue<'a, T>>) -> Sender<'a, T> {
        Sender(q.clone())
    }

    pub fn send(&self, data: T) -> bool {
        while self.0.enqueue(data.clone()).is_err() {}
        true
    }

    pub fn try_send(&self, data: T) -> bool {
        self.0.enqueue(data).is_ok()
    }
}

#[repr(transparent)]
pub struct Receiver<'a, T>(Arc<Queue<'a, T>>);

unsafe impl<'a, T: Send> Send for Receiver<'a, T> {}
unsafe impl<'a, T: Sync> Sync for Receiver<'a, T> {}

impl<'a, T: Send> Receiver<'a, T> {
    pub fn with_capacity_in<A: Allocator>(capacity: usize, alloc: A) -> Receiver<'a, T> {
        Receiver(Arc::new(
            Queue::<T>::with_capacity_in(true, capacity, alloc).unwrap(),
        ))
    }

    pub fn with_shared_queue(q: Arc<Queue<'a, T>>) -> Receiver<'a, T> {
        Receiver(q.clone())
    }

    pub fn recv(&self) -> T {
        loop {
            if let Some(data) = self.0.dequeue() {
                return data;
            }
        }
    }

    pub fn try_recv(&self) -> Option<T> {
        self.0.dequeue()
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
        sender.send(send_data);

        let rx_data: [u8; 10] = receiver.recv();
        assert_eq!(&send_data, &rx_data[0..send_data.len()]);
    }
}
