use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use crossbeam_queue::{ArrayQueue, PushError};
use lazy_static::lazy_static;

use super::memory::{VAddr, BASE_PAGE_SIZE};
use crate::is_page_aligned;
use crate::process::Pid;

// In the xAPIC mode, the Destination Format Register (DFR) through the MMIO interface determines the choice of a
// flat logical mode or a clustered logical mode. Flat logical mode is not supported in the x2APIC mode. Hence the
// Destination Format Register (DFR) is eliminated in x2APIC mode.
// The 32-bit logical x2APIC ID field of LDR is partitioned into two sub-fields:
//
// • Cluster ID (LDR[31:16]): is the address of the destination cluster
// • Logical ID (LDR[15:0]): defines a logical ID of the individual local x2APIC within the cluster specified by
//   LDR[31:16].
//
// In x2APIC mode, the 32-bit logical x2APIC ID, which can be read from LDR, is derived from the 32-bit local x2APIC ID:
// Logical x2APIC ID = [(x2APIC ID[19:4] « 16) | (1 « x2APIC ID[3:0])]

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

pub fn shootdown(pid: Pid, range: Range<u64>) {}
