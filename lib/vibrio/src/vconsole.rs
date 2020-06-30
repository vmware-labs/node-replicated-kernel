//! A simple virtual console for user-space programs (getchar et. al.).
//!
//! Needs to be a proper serial driver.

//use crossbeam_queue::{ArrayQueue, PushError};
use lazy_static::lazy_static;

static COM1_IRQ: u64 = 4 + 32;

/*lazy_static! {
    pub static ref VBUFFER: ArrayQueue<char> = ArrayQueue::new(12);
}*/

pub fn init() {
    //lazy_static::initialize(&VBUFFER);
    crate::syscalls::Irq::irqalloc(COM1_IRQ, 0).ok();
}

fn getchar() -> Option<char> {
    None
}
