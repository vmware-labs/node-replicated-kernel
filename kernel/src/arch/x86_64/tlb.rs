use core::ops::Range;
use crossbeam_queue::{ArrayQueue, PushError};
use lazy_static::lazy_static;

#[derive(Eq, PartialEq, Debug)]
struct Shootdown {
    vregion: Range<usize>,
}

lazy_static! {
    static ref CHANNEL: ArrayQueue<Shootdown> = ArrayQueue::new(2);
}

pub fn enqueue() {
    let msg = Shootdown { vregion: 0..10 };
    error!("TLB enqueue shootdown msg {:?}", msg);
    assert_eq!(CHANNEL.push(msg), Ok(()));
}

pub fn dequeue() {
    let msg = CHANNEL.pop();
    error!("TLB channel got msg {:?}", msg);
}
