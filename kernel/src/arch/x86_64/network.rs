use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vmxnet3::pci::BarAccess;
use vmxnet3::smoltcp::DevQueuePhy;
use vmxnet3::vmx::VMXNet3;

use crate::memory::vspace::MapAction;
use crate::memory::PAddr;
use crate::pci::claim_device;
use kpi::KERNEL_BASE;

#[cfg(feature = "shmem")]
use {
    alloc::sync::Arc,
    rpc::transport::shmem::allocator::ShmemAllocator,
    rpc::transport::shmem::Queue,
    rpc::transport::shmem::{Receiver, Sender},
    rpc::transport::ShmemTransport,
};

use smoltcp::iface::{Interface, InterfaceBuilder, NeighborCache, Routes};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

pub fn init_network<'a>() -> Interface<'a, DevQueuePhy> {
    const VMWARE_INC: u16 = 0x15ad;
    const VMXNET_DEV: u16 = 0x07b0;
    let pci = if let Some(vmxnet3_dev) = claim_device(VMWARE_INC, VMXNET_DEV) {
        let addr = vmxnet3_dev.pci_address();
        BarAccess::new(addr.bus.into(), addr.dev.into(), addr.fun.into())
    } else {
        panic!("vmxnet3 PCI device not found, forgot to pass `--nic vmxnet3`?");
    };

    // TODO(hack): Map potential vmxnet3 bar addresses XD
    // Do this in kernel space (offset of KERNEL_BASE) so the mapping persists
    let kcb = super::kcb::get_kcb();
    for &bar in &[pci.bar0 - KERNEL_BASE, pci.bar1 - KERNEL_BASE] {
        kcb.arch
            .init_vspace()
            .map_identity_with_offset(
                PAddr::from(KERNEL_BASE),
                PAddr::from(bar),
                0x1000,
                MapAction::ReadWriteKernel,
            )
            .expect("Failed to write potential vmxnet3 bar addresses")
    }

    // Create the VMX device
    let mut vmx = VMXNet3::new(pci, 1, 1).unwrap();
    vmx.attach_pre().expect("Failed to vmx.attach_pre()");
    vmx.init();

    // Create the EthernetInterface wrapping the VMX device
    let device = DevQueuePhy::new(vmx).expect("Can't create PHY");
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    // TODO: MAC, IP, and default route should be dynamic
    #[cfg(not(feature = "exokernel"))]
    let ethernet_addr = EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xdc]);

    #[cfg(feature = "exokernel")]
    let ethernet_addr = EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xdd]);

    #[cfg(not(feature = "exokernel"))]
    let ip_addrs = [IpCidr::new(IpAddress::v4(172, 31, 0, 11), 24)];

    #[cfg(feature = "exokernel")]
    let ip_addrs = [IpCidr::new(IpAddress::v4(172, 31, 0, 12), 24)];

    let mut routes = Routes::new(BTreeMap::new());
    routes
        .add_default_ipv4_route(Ipv4Address::new(172, 31, 0, 20))
        .unwrap();

    // Create SocketSet w/ space for 1 socket
    let mut sock_vec = Vec::new();
    sock_vec.try_reserve_exact(1).unwrap();
    let iface = InterfaceBuilder::new(device, sock_vec)
        .ip_addrs(ip_addrs)
        .hardware_addr(ethernet_addr.into())
        .routes(routes)
        .neighbor_cache(neighbor_cache)
        .finalize();
    iface
}

/// Setup inter-vm shared-memory device.
pub fn init_shmem_device() -> Option<(u64, u64)> {
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
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .init_vspace()
            .map_identity_with_offset(
                PAddr::from(KERNEL_BASE),
                PAddr::from(base_paddr),
                size as usize,
                MapAction::ReadWriteKernel,
            )
            .expect("Failed to write potential shmem bar addresses");

        Some((base_paddr, size))
    } else {
        log::error!("Unable to find IVSHMEM device");
        None
    }
}

#[cfg(feature = "shmem")]
pub fn create_shmem_transport() -> Result<ShmemTransport<'static>, ()> {
    if let Some((base_addr, size)) = init_shmem_device() {
        let allocator = ShmemAllocator::new(base_addr + KERNEL_BASE, size);
        #[cfg(feature = "controller")]
        {
            let server_to_client_queue =
                Arc::new(Queue::<Vec<u8>>::with_capacity_in(true, 1024, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::<Vec<u8>>::with_capacity_in(true, 1024, &allocator).unwrap());
            let server_sender = Sender::with_shared_queue(server_to_client_queue.clone());
            let server_receiver = Receiver::with_shared_queue(client_to_server_queue.clone());
            log::debug!("Controller: Created shared-memory transport!");
            Ok(ShmemTransport::new(server_receiver, server_sender))
        }
        #[cfg(not(feature = "controller"))]
        {
            let server_to_client_queue =
                Arc::new(Queue::<Vec<u8>>::with_capacity_in(false, 1024, &allocator).unwrap());
            let client_to_server_queue =
                Arc::new(Queue::<Vec<u8>>::with_capacity_in(false, 1024, &allocator).unwrap());
            let client_receiver = Receiver::with_shared_queue(server_to_client_queue.clone());
            let client_sender = Sender::with_shared_queue(client_to_server_queue.clone());
            log::debug!("Client: Created shared-memory transport!");
            Ok(ShmemTransport::new(client_receiver, client_sender))
        }
    } else {
        log::error!("Failed to create shared-memory transport");
        Err(())
    }
}
