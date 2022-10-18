// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use kpi::KERNEL_BASE;
use lazy_static::lazy_static;
use rpc::rpc::MAX_BUFF_LEN;
use static_assertions::const_assert;

#[cfg(feature = "rackscale")]
use {crate::arch::rackscale::controller::FrameCacheMemslice, rpc::transport::ShmemTransport};

use crate::cmdline::Transport;
use crate::error::{KError, KResult};
use crate::memory::vspace::MapAction;
use crate::memory::{Frame, PAddr};
use crate::pci::claim_device;

pub(crate) struct ShmemRegion {
    pub base_addr: u64,
    pub size: u64,
}

lazy_static! {
    pub(crate) static ref SHMEM_REGION: ShmemRegion = {
        let (base_addr, size) = init_shmem_device().expect("Failed to init shmem device");
        ShmemRegion { base_addr, size }
    };
}

pub(crate) const MAX_SHMEM_TRANSPORT_SIZE: u64 = 2 * 1024 * 1024;

// The default size of the Shared memory queue is 32.
// The total size of two queues(sender and reciever) should be less
// that the MAX_SHMEM_TRANSPORT_SIZE.
const SHMEM_QUEUE_SIZE: usize = 32;
const_assert!(2 * SHMEM_QUEUE_SIZE * MAX_BUFF_LEN <= MAX_SHMEM_TRANSPORT_SIZE as usize);

/// Setup inter-vm shared-memory device.
#[allow(unused)]
pub(crate) fn init_shmem_device() -> KResult<(u64, u64)> {
    const RED_HAT_INC: u16 = 0x1af4;
    const INTER_VM_SHARED_MEM_DEV: u16 = 0x1110;
    if let Some(mut ivshmem_device) = claim_device(RED_HAT_INC, INTER_VM_SHARED_MEM_DEV) {
        let mem_region = ivshmem_device.bar(2).expect("Unable to find the BAR");
        let base_paddr = mem_region.address;
        let size = mem_region.size;
        log::info!(
            "Found IVSHMEM device with base paddr {:X} and size {}",
            base_paddr,
            size
        );

        // If the PCI dev is not the bus master; make it.
        if !ivshmem_device.is_bus_master() {
            ivshmem_device.enable_bus_mastering();
        }

        // TODO: Double check if this is mapping we need?
        let mut kvspace = crate::arch::vspace::INITIAL_VSPACE.lock();
        kvspace
            .map_identity_with_offset(
                PAddr::from(KERNEL_BASE),
                PAddr::from(base_paddr),
                size as usize,
                MapAction::kernel() | MapAction::write(),
            )
            .expect("Failed to write potential shmem bar addresses");
        Ok((base_paddr, size))
    } else {
        log::error!("Unable to find IVSHMEM device");
        Err(KError::IvShmemDeviceNotFound)
    }
}

#[cfg(feature = "rpc")]
pub(crate) fn create_shmem_transport(client_id: u64) -> KResult<ShmemTransport<'static>> {
    use crate::arch::rackscale::client::get_num_clients;
    use crate::cmdline::Mode;
    use alloc::sync::Arc;
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::Queue;
    use rpc::transport::shmem::{Receiver, Sender};

    assert!(client_id * MAX_SHMEM_TRANSPORT_SIZE <= SHMEM_REGION.size);
    let transport_size = core::cmp::min(
        SHMEM_REGION.size / get_num_clients(),
        MAX_SHMEM_TRANSPORT_SIZE,
    );
    let base_addr = SHMEM_REGION.base_addr + KERNEL_BASE + client_id * transport_size;
    let allocator = ShmemAllocator::new(base_addr, transport_size);
    match crate::CMDLINE.get().map_or(Mode::Native, |c| c.mode) {
        Mode::Controller => {
            let server_to_client_queue =
                Arc::new(Queue::with_capacity_in(true, SHMEM_QUEUE_SIZE, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::with_capacity_in(true, SHMEM_QUEUE_SIZE, &allocator).unwrap());
            let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
            let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
            log::info!(
                "Controller: Created shared-memory transport for machine {}! size={:?}, base={:?}",
                client_id,
                transport_size,
                base_addr
            );
            Ok(ShmemTransport::new(server_receiver, server_sender))
        }
        Mode::Client => {
            let server_to_client_queue =
                Arc::new(Queue::with_capacity_in(false, SHMEM_QUEUE_SIZE, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::with_capacity_in(false, SHMEM_QUEUE_SIZE, &allocator).unwrap());
            let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
            let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
            log::info!(
                "Client: Created shared-memory transport! size={:?}, base={:?}",
                transport_size,
                base_addr
            );
            Ok(ShmemTransport::new(client_receiver, client_sender))
        }
        Mode::Native => {
            log::error!("Native mode not supported for shmem");
            Err(KError::InvalidNativeMode)
        }
    }
}

#[cfg(feature = "rpc")]
pub(crate) fn init_shmem_rpc(
    send_client_data: bool, // This field is used to indicate if init_client() should send ClientRegistrationRequest
) -> KResult<Box<rpc::client::Client>> {
    use crate::arch::rackscale::client::get_local_client_id;
    use crate::arch::rackscale::registration::initialize_client;
    use rpc::client::Client;

    // Set up the transport
    let transport = Box::try_new(create_shmem_transport(get_local_client_id())?)?;

    // Create the client
    let client = Box::try_new(Client::new(transport))?;
    initialize_client(client, send_client_data)
}

#[cfg(feature = "rackscale")]
pub(crate) fn get_affinity_shmem() -> (u64, u64) {
    use crate::arch::rackscale::client::{get_local_client_id, get_num_clients};

    let mut base_offset = 0;
    let mut size = SHMEM_REGION.size;
    let num_clients = get_num_clients();

    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        // Offset base to ignore shmem used for client transports
        base_offset += MAX_SHMEM_TRANSPORT_SIZE * num_clients;

        // Remove amount used for transport from the size
        size = core::cmp::max(0, size - MAX_SHMEM_TRANSPORT_SIZE * num_clients);
    };

    size = size / num_clients;
    base_offset += size * get_local_client_id();
    log::debug!(
        "Shmem affinity region: offset={:x?}, size={:x?}",
        base_offset,
        size,
    );

    (base_offset, size)
}

#[cfg(feature = "rackscale")]
pub(crate) fn create_shmem_manager(
    base: u64,
    size: u64,
    client_id: u64,
) -> Option<Box<FrameCacheMemslice>> {
    if size > 0 {
        // Using client_id as affinity, but that's probably not really correct here
        let frame = Frame::new(PAddr(base), size as usize, client_id as usize);
        let mut shmem_cache = Box::new(FrameCacheMemslice::new(0));
        shmem_cache.populate_2m_first(frame);
        Some(shmem_cache)
    } else {
        None
    }
}
