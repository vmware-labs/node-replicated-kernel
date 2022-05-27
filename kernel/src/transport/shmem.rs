// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use kpi::KERNEL_BASE;
#[cfg(feature = "rpc")]
use rpc::transport::ShmemTransport;

use crate::error::{KError, KResult};
use crate::memory::vspace::MapAction;
use crate::memory::PAddr;
use crate::pci::claim_device;

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
    use rpc::rpc::PacketBuffer;
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::Queue;
    use rpc::transport::shmem::{Receiver, Sender};

    let (base_addr, size) = init_shmem_device()?;
    let allocator = ShmemAllocator::new(base_addr + KERNEL_BASE, size);
    match crate::CMDLINE.get().map_or(Mode::Native, |c| c.mode) {
        Mode::Controller => {
            let server_to_client_queue =
                Arc::new(Queue::<PacketBuffer>::with_capacity_in(true, 32, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::<PacketBuffer>::with_capacity_in(true, 32, &allocator).unwrap());
            let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
            let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
            log::info!("Controller: Created shared-memory transport!");
            Ok(ShmemTransport::new(server_receiver, server_sender))
        }
        Mode::Client => {
            let server_to_client_queue =
                Arc::new(Queue::<PacketBuffer>::with_capacity_in(false, 32, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::<PacketBuffer>::with_capacity_in(false, 32, &allocator).unwrap());
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
pub(crate) fn init_shmem_rpc() -> KResult<alloc::boxed::Box<rpc::client_shmem::ShmemClient>> {
    use alloc::boxed::Box;
    use rpc::client_shmem::ShmemClient;
    use rpc::RPCClient;

    // Set up the transport
    let transport = Box::try_new(create_shmem_transport()?)?;

    // Create the client
    let mut client = Box::try_new(ShmemClient::new(transport))?;
    client.connect()?;
    Ok(client)
}
