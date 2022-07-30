// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use kpi::KERNEL_BASE;
use lazy_static::lazy_static;
#[cfg(feature = "rpc")]
use rpc::transport::ShmemTransport;

use crate::cmdline::Transport;
use crate::error::{KError, KResult};
use crate::memory::mcache::FrameCacheLarge;
use crate::memory::vspace::MapAction;
use crate::memory::{Frame, PAddr};
use crate::pci::claim_device;

pub(crate) struct ShmemRegion {
    pub base_kaddr: u64,
    pub size: u64,
}

lazy_static! {
    pub(crate) static ref SHMEM_REGION: ShmemRegion = {
        let (base_addr, size) = init_shmem_device().expect("Failed to init shmem device");
        ShmemRegion {
            base_kaddr: KERNEL_BASE + base_addr,
            size,
        }
    };
}

pub(crate) const MAX_SHMEM_TRANSPORT_SIZE: u64 = 2 * 1024 * 1024;

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
                MapAction::ReadWriteKernel,
            )
            .expect("Failed to write potential shmem bar addresses");

        Ok((base_paddr, size))
    } else {
        log::error!("Unable to find IVSHMEM device");
        Err(KError::IvShmemDeviceNotFound)
    }
}

#[cfg(feature = "rpc")]
pub(crate) fn create_shmem_transport() -> KResult<ShmemTransport<'static>> {
    use crate::cmdline::Mode;
    use alloc::sync::Arc;
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::Queue;
    use rpc::transport::shmem::{Receiver, Sender};

    let transport_size = core::cmp::min(SHMEM_REGION.size, MAX_SHMEM_TRANSPORT_SIZE);
    let allocator = ShmemAllocator::new(SHMEM_REGION.base_kaddr, transport_size);
    match crate::CMDLINE.get().map_or(Mode::Native, |c| c.mode) {
        Mode::Controller => {
            let server_to_client_queue =
                Arc::new(Queue::with_capacity_in(true, 32, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::with_capacity_in(true, 32, &allocator).unwrap());
            let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
            let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
            log::info!("Controller: Created shared-memory transport!");
            Ok(ShmemTransport::new(server_receiver, server_sender))
        }
        Mode::Client => {
            let server_to_client_queue =
                Arc::new(Queue::with_capacity_in(false, 32, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::with_capacity_in(false, 32, &allocator).unwrap());
            let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
            let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
            log::info!("Client: Created shared-memory transport!");
            Ok(ShmemTransport::new(client_receiver, client_sender))
        }
        Mode::Native => {
            log::error!("Native mode not supported for shmem");
            Err(KError::InvalidNativeMode)
        }
    }
}

#[cfg(feature = "rpc")]
pub(crate) fn init_shmem_rpc() -> KResult<alloc::boxed::Box<rpc::client::Client>> {
    use rpc::client::Client;
    use rpc::RPCClient;

    // Set up the transport
    let transport = Box::try_new(create_shmem_transport()?)?;

    // Create the client
    let mut client = Box::try_new(Client::new(transport))?;
    client.connect()?;
    Ok(client)
}

#[cfg(feature = "rackscale")]
pub(crate) fn create_shmem_manager() -> Option<Box<FrameCacheLarge>> {
    // Create remote memory frame
    let base: PAddr = PAddr::from(SHMEM_REGION.base_kaddr);
    let frame_size = if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Ethernet)
    {
        // Subtract memory used for transport if using shmem transport
        core::cmp::min(0, SHMEM_REGION.size - MAX_SHMEM_TRANSPORT_SIZE)
    } else {
        SHMEM_REGION.size
    };

    // If there is shared memory available, create memory frame for cache
    if frame_size > 0 {
        let shmem_frame = Frame::new(base, frame_size as usize, 0);
        assert!(shmem_frame != Frame::empty());

        // Allocate memory manager in local memory, and populate with shmem
        let mut shmem_cache = Box::new(FrameCacheLarge::new(0));
        shmem_cache.populate_2m_first(shmem_frame);
        Some(shmem_cache)
    } else {
        None
    }
}
