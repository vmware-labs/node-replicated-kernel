use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use crossbeam_queue::{ArrayQueue, PushError};
use lazy_static::lazy_static;

use super::memory::{VAddr, BASE_PAGE_SIZE};
use crate::is_page_aligned;

lazy_static! {
    static ref TLB_WORKQUEUE: Vec<ArrayQueue<Arc<Shootdown>>> = {
        let cores = topology::MACHINE_TOPOLOGY.num_threads();
        let mut channels = Vec::with_capacity(cores);
        for i in 0..cores {
            channels.push(ArrayQueue::new(4));
        }

        channels
    };
}

#[derive(Debug)]
pub struct Shootdown {
    vregion: Range<u64>,
    ack: AtomicBool,
}

impl Shootdown {
    /// Create a new shootdown request.
    pub fn new(vregion: Range<u64>) -> Self {
        debug_assert!(is_page_aligned!(vregion.start));
        debug_assert!(is_page_aligned!(vregion.end));
        Shootdown {
            vregion,
            ack: AtomicBool::new(false),
        }
    }

    /// Acknowledge shootdown to sender/requestor core.
    fn acknowledge(&self) {
        self.ack.store(true, Ordering::Relaxed);
    }

    /// Check if receiver has acknowledged the shootdown.
    pub fn is_acknowledged(&self) -> bool {
        self.ack.load(Ordering::Relaxed)
    }

    /// Flush the TLB entries.
    fn process(&self) {
        // Safe to acknowledge first as we won't return/interrupt
        // before this function completes:
        self.acknowledge();

        let it = self.vregion.clone().step_by(BASE_PAGE_SIZE);
        if it.count() > 20 {
            trace!("flush the entire TLB");
            unsafe { x86::tlb::flush_all() };
        } else {
            let it = self.vregion.clone().step_by(BASE_PAGE_SIZE);
            for va in it {
                trace!("flushing TLB page {:#x}", va);
                unsafe { x86::tlb::flush(va as usize) };
            }
        }
    }
}

pub fn enqueue(apic_id: usize, s: Arc<Shootdown>) {
    trace!("TLB enqueue shootdown msg {:?}", s);
    assert!(TLB_WORKQUEUE[apic_id].push(s).is_ok());
}

pub fn dequeue(apic_id: usize) {
    let msg = TLB_WORKQUEUE[apic_id].pop().unwrap();
    trace!("TLB channel got msg {:?}", msg);
    msg.process();
}
