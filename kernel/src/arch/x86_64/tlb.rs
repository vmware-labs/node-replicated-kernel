// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use apic::ApicDriver;
use bit_field::BitField;
use crossbeam_queue::ArrayQueue;
use fallible_collections::FallibleVecGlobal;
use lazy_static::lazy_static;
use log::trace;
use x86::apic::{
    ApicId, DeliveryMode, DeliveryStatus, DestinationMode, DestinationShorthand, Icr, Level,
    TriggerMode,
};

use super::memory::BASE_PAGE_SIZE;
use crate::fs::cnrfs;
use crate::memory::vspace::TlbFlushHandle;
use crate::{is_page_aligned, nr};

// In the xAPIC mode, the Destination Format Register (DFR) through the MMIO
// interface determines the choice of a flat logical mode or a clustered logical
// mode. Flat logical mode is not supported in the x2APIC mode. Hence the
// Destination Format Register (DFR) is eliminated in x2APIC mode. The 32-bit
// logical x2APIC ID field of LDR is partitioned into two sub-fields:
//
// • Cluster ID (LDR[31:16]): is the address of the destination cluster
//
// • Logical ID (LDR[15:0]): defines a logical ID of the individual local x2APIC
// within the cluster specified by LDR[31:16].
//
// In x2APIC mode, the 32-bit logical x2APIC ID, which can be read from LDR, is
// derived from the 32-bit local x2APIC ID: Logical x2APIC ID = [(x2APIC
// ID[19:4] « 16) | (1 « x2APIC ID[3:0])]

#[cfg(feature = "rackscale")]
const REMOTE_WORKQUEUE_CAPACITY: usize = 4;

#[cfg(feature = "rackscale")]
lazy_static! {
    pub(crate) static ref RACKSCALE_CLIENT_WORKQUEUES: Arc<Vec<ArrayQueue<WorkItem>>> = {
        #[cfg(feature = "rackscale")]
        if crate::CMDLINE
            .get()
            .map_or(false, |c| c.mode == crate::cmdline::Mode::Controller)
        {
            use crate::memory::SHARED_AFFINITY;
            use crate::arch::kcb::per_core_mem;

            // We want to allocate the queues in shared memory
            let affinity = {
                let pcm = per_core_mem();
                let affinity = { pcm.physical_memory.borrow().affinity };
                pcm.set_mem_affinity(SHARED_AFFINITY).expect("Can't change affinity");
                affinity
            };

            let num_clients = *crate::environment::NUM_MACHINES - 1;
            let mut channels =
                Vec::try_with_capacity(num_clients).expect("Not enough memory to initialize system");
            for _i in 0..num_clients {
                // ArrayQueue does memory allocation on `new`, maybe have try_new,
                // but this is fine since it's during initialization
                channels.push(ArrayQueue::new(REMOTE_WORKQUEUE_CAPACITY));
            }

            let channels = Arc::new(channels);

            // Reset mem allocator to use per core memory again
            if affinity != SHARED_AFFINITY {
                let pcm = per_core_mem();
                pcm.set_mem_affinity(affinity).expect("Can't change affinity");
            }

            channels
        } else {
            // Get location of the work queues from the controller, who will have already created them in shared memory
            use crate::arch::rackscale::get_workqueues::rpc_get_workqueues;
            use crate::arch::rackscale::CLIENT_STATE;
            let mut client = CLIENT_STATE.rpc_client.lock();
            rpc_get_workqueues(&mut **client).expect("Failed to get shared memory workqueues from the controller")
        }
    };
}

const IPI_WORKQUEUE_CAPACITY: usize = 4;

lazy_static! {
    static ref IPI_WORKQUEUE: Vec<ArrayQueue<WorkItem>> = {
        let num_threads = atopology::MACHINE_TOPOLOGY.num_threads();
        let mut channels =
            Vec::try_with_capacity(num_threads).expect("Not enough memory to initialize system");
        for _i in 0..num_threads {
            // ArrayQueue does memory allocation on `new`, maybe have try_new,
            // but this is fine since it's during initialization
            channels.push(ArrayQueue::new(IPI_WORKQUEUE_CAPACITY));
        }

        channels
    };
}

#[derive(Debug)]
pub(crate) enum WorkItem {
    Shootdown(Arc<Shootdown>),
    AdvanceReplica(usize),
}

#[derive(Debug)]
pub(crate) struct Shootdown {
    vregion: Range<u64>,
    ack: AtomicBool,
}

impl Shootdown {
    /// Create a new shootdown request.
    pub(crate) fn new(vregion: Range<u64>) -> Self {
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
    pub(crate) fn is_acknowledged(&self) -> bool {
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

pub(crate) fn enqueue(mtid: kpi::system::MachineThreadId, s: WorkItem) {
    trace!("TLB enqueue shootdown msg {:?}", s);
    let _ignore = IPI_WORKQUEUE[mtid as usize].push(s);
}

pub(crate) fn dequeue(mtid: kpi::system::MachineThreadId) {
    match IPI_WORKQUEUE[mtid as usize].pop() {
        Some(msg) => match msg {
            WorkItem::Shootdown(s) => {
                trace!("TLB channel got msg {:?}", s);
                s.process();
            }
            WorkItem::AdvanceReplica(log_id) => advance_log(log_id),
        },
        None => { /*IPI request was handled by eager_advance_fs_replica()*/ }
    }
}

fn advance_log(log_id: usize) {
    // All metadata operations are done using log 1. So, make sure that the
    // replica has applied all those operation before any other log sync.
    if log_id != 1 {
        match cnrfs::MlnrKernelNode::synchronize_log(1) {
            Ok(_) => { /* Simply return */ }
            Err(e) => unreachable!("Error {:?} while advancing the log 1", e),
        }
    }
    match cnrfs::MlnrKernelNode::synchronize_log(log_id) {
        Ok(_) => { /* Simply return */ }
        Err(e) => unreachable!("Error {:?} while advancing the log {}", e, log_id),
    }
}

pub(crate) fn eager_advance_fs_replica() {
    let core_id = kpi::system::mtid_from_gtid(*crate::environment::CORE_ID);

    match IPI_WORKQUEUE[core_id].pop() {
        Some(msg) => {
            match &msg {
                WorkItem::Shootdown(_s) => {
                    // If its for TLB shootdown, insert it back into the queue.
                    enqueue(core_id, msg)
                }
                WorkItem::AdvanceReplica(log_id) => advance_log(*log_id),
            }
        }
        None => {
            let cnrfs = crate::fs::cnrfs::CNRFS.borrow();
            match cnrfs.as_ref() {
                Some(replica) => {
                    let log_id = replica.1.id();
                    // Synchronize NR-replica
                    let _ignore = nr::KernelNode::synchronize();
                    // Synchronize Mlnr-replica.
                    advance_log(log_id);
                }
                None => unreachable!("eager_advance_fs_replica: CNRFS not yet initialized!"),
            };
        }
    }
}

pub(crate) fn send_ipi_to_apic(apic_id: ApicId) {
    let mut apic = super::irq::LOCAL_APIC.borrow_mut();

    let icr = Icr::for_x2apic(
        super::irq::MLNR_GC_INIT,
        apic_id,
        DestinationShorthand::NoShorthand,
        DeliveryMode::Fixed,
        DestinationMode::Physical,
        DeliveryStatus::Idle,
        Level::Assert,
        TriggerMode::Edge,
    );

    unsafe { apic.send_ipi(icr) }
}

fn send_ipi_multicast(ldr: u32) {
    let mut apic = super::irq::LOCAL_APIC.borrow_mut();

    let icr = Icr::for_x2apic(
        super::irq::TLB_WORK_PENDING,
        // TODO(api): this is technically not an APIC id, should probably change the interface
        ApicId::X2Apic(ldr),
        DestinationShorthand::NoShorthand,
        DeliveryMode::Fixed,
        DestinationMode::Logical,
        DeliveryStatus::Idle,
        Level::Assert,
        TriggerMode::Edge,
    );

    unsafe { apic.send_ipi(icr) }
}

/// Runs the TLB shootdown protocol.
///
/// Takes the `TlbFlushHandle` and figures out what cores it needs to send an IPI to.
/// It divides IPIs into clusters to avoid overhead of sending IPIs individually.
/// Finally, waits until all cores have acknowledged the IPI before it returns.
pub(crate) fn shootdown(handles: Vec<TlbFlushHandle>) {
    let my_mtid = kpi::system::mtid_from_gtid(*crate::environment::CORE_ID);
    let my_mid = kpi::system::mid_from_gtid(*crate::environment::CORE_ID);

    let handle = &handles[my_mid];

    #[cfg(feature = "rackscale")]
    {
        use crate::arch::irq::REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR;
        use crate::transport::shmem::SHMEM_DEVICE;

        // Skip the first one - that's the controller
        for i in 1..handles.len() {
            if i != my_mid {
                // TODO: add handles[i] to queue for machine
                log::warn!(
                    "Need to send TLB flush to remote machine id={:?}, is_empty={:?}",
                    i,
                    handles[i].core_map.is_empty()
                );
                SHMEM_DEVICE
                    .set_doorbell(REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR, i.try_into().unwrap());
            }
        }
    }

    // We support up to 16 IPI clusters, this will address `16*16 = 256` cores
    // Cluster ID (LDR[31:16]) is the address of the destination cluster
    // We pre-configure the upper half (cluster ID) of LDR here
    // by initializing the elements
    let mut cluster_destination: [u32; 16] = [
        0 << 16,
        1 << 16,
        2 << 16,
        3 << 16,
        4 << 16,
        5 << 16,
        6 << 16,
        7 << 16,
        8 << 16,
        9 << 16,
        10 << 16,
        11 << 16,
        12 << 16,
        13 << 16,
        14 << 16,
        15 << 16,
    ];

    let num_cores = atopology::MACHINE_TOPOLOGY.num_threads();
    let mut shootdowns: Vec<Arc<Shootdown>> = Vec::try_with_capacity(num_cores)
        .expect("TODO(error-handling): ideally: no possible failure during shootdown");
    let range = handle.vaddr.as_u64()..(handle.vaddr + handle.size).as_u64();

    for mtid in handle.cores() {
        if mtid != my_mtid {
            let apic_id = atopology::MACHINE_TOPOLOGY.threads[mtid].apic_id();
            let cluster_addr = apic_id.x2apic_logical_cluster_address();
            let cluster = apic_id.x2apic_logical_cluster_id();

            trace!(
                "Send shootdown to mtid:{} in cluster:{} cluster_addr:{}",
                mtid,
                cluster,
                cluster_addr
            );
            cluster_destination[cluster as usize].set_bit(cluster_addr as usize, true);

            let shootdown = Arc::try_new(Shootdown::new(range.clone()))
                .expect("TODO(error-handling): ideally: no possible failure during shootdown");
            enqueue(mtid, WorkItem::Shootdown(shootdown.clone()));

            debug_assert!(shootdowns.len() < shootdowns.capacity(), "Avoid realloc");
            shootdowns.push(shootdown);
        }
    }

    // Notify the cores in all clusters of new work in the queue
    for cluster_ldr in cluster_destination {
        // Do we need to send to anyone inside this cluster?
        if cluster_ldr.get_bits(0..=3) != 0 {
            trace!("send ipi multicast to {}", cluster_ldr);
            send_ipi_multicast(cluster_ldr);
        }
    }

    // Finally, we also need to shootdown our own TLB
    let shootdown = Shootdown::new(range);
    shootdown.process();

    // Wait synchronously on cores to complete

    // start time = now
    while !shootdowns.is_empty() {
        // Make progress on our work while we wait for others
        dequeue(my_mtid);

        shootdowns.drain_filter(|s| s.is_acknowledged());
        core::hint::spin_loop();
    }

    trace!("done with all shootdowns");
}

pub(crate) fn advance_replica(mtid: kpi::system::MachineThreadId, log_id: usize) {
    trace!("Send AdvanceReplica IPI for {} to {}", log_id, mtid);
    let apic_id = atopology::MACHINE_TOPOLOGY.threads[mtid as usize].apic_id();

    enqueue(mtid, WorkItem::AdvanceReplica(log_id));
    send_ipi_to_apic(apic_id);
}
