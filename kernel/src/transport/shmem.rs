// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::sync::Arc;
use driverkit::pci::{CapabilityId, CapabilityType, PciDevice};
use kpi::KERNEL_BASE;
use lazy_static::lazy_static;
use rpc::rpc::MAX_BUFF_LEN;
use spin::Mutex;
use static_assertions::const_assert;

#[cfg(feature = "rackscale")]
use {crate::arch::rackscale::controller::FrameCacheMemslice, rpc::transport::ShmemTransport};

use crate::cmdline::Transport;
use crate::error::{KError, KResult};
use crate::memory::vspace::MapAction;
use crate::memory::{paddr_to_kernel_vaddr, Frame, PAddr, BASE_PAGE_SIZE};
use crate::pci::claim_device;

// Register information from:
// https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt
// other fields are reserved for revision 1
const SHMEM_IVPOSITION_OFFSET: u64 = 8;
const SHMEM_DOORBELL_OFFSET: u64 = 12;

// Used for rackscale mode
pub(crate) const MAX_SHMEM_TRANSPORT_SIZE: u64 = 2 * 1024 * 1024;

lazy_static! {
    pub(crate) static ref SHMEM_DEVICE: ShmemDevice =
        ShmemDevice::new().expect("Failed to get SHMEM device");
}

pub(crate) struct ShmemDevice {
    // Shmem memory region.
    pub(crate) mem_addr: u64,
    pub(crate) mem_size: u64,

    // Easier to remember here so we can reference without gaining interrupt regiister mutex
    pub(crate) id: u16,

    // Doorbell address protected by arc<mutex<>> to prevent concurrent writes
    doorbell: Arc<Mutex<u64>>,

    // ivshmem PciDevice
    device: Arc<Mutex<PciDevice>>,
}

impl ShmemDevice {
    /// Assume this method is only called once per device
    pub(crate) fn new() -> Option<ShmemDevice> {
        const RED_HAT_INC: u16 = 0x1af4;
        const INTER_VM_SHARED_MEM_DEV: u16 = 0x1110;

        if let Some(mut ivshmem_device) = claim_device(RED_HAT_INC, INTER_VM_SHARED_MEM_DEV) {
            log::info!(
                "shmem revision: {:?}",
                ivshmem_device.revision_and_class().0
            );
            let register_region = ivshmem_device.bar(0).expect("Unable to find shmem BAR0");
            log::info!(
                "Found IVSHMEM device register region with base paddr {:X} and size {}",
                register_region.address,
                register_region.size
            );

            let mem_region = ivshmem_device.bar(2).expect("Unable to find shmem BAR2");
            log::info!(
                "Found IVSHMEM device memory region with base paddr {:X} and size {}",
                mem_region.address,
                mem_region.size
            );

            let msi_region = if let Some(cap) = ivshmem_device
                .capabilities()
                .find(|cap| cap.id == CapabilityId::MsiX)
            {
                log::info!("Device has capability {:?}", cap.id);
                if let CapabilityType::MsiX(msi) = ivshmem_device.get_cap_region_mut(cap) {
                    log::info!(
                        "Device MSI-X table is at bar {} offset {} table size is {}",
                        msi.bir(),
                        msi.table_offset(),
                        msi.table_size()
                    );

                    let bar = msi.bir();
                    ivshmem_device.bar(bar)
                } else {
                    None
                }
            } else {
                None
            }
            .expect("Failed to get msi region");

            // If the PCI dev is not the bus master; make it.
            if !ivshmem_device.is_bus_master() {
                ivshmem_device.enable_bus_mastering();
            }

            // Map register region into kernel space
            let mut kvspace = crate::arch::vspace::INITIAL_VSPACE.lock();
            kvspace
                .map_identity_with_offset(
                    PAddr::from(KERNEL_BASE),
                    PAddr::from(register_region.address),
                    // TODO(hunhoffe): this is a hack because the region is < BASE_PAGE_REGION
                    core::cmp::max(BASE_PAGE_SIZE, register_region.size as usize),
                    MapAction::kernel() | MapAction::write(),
                )
                .expect("Failed to write potential shmem register region addresses");

            // Get ID assigned by shmem server
            let id_ptr =
                (register_region.address + KERNEL_BASE + SHMEM_IVPOSITION_OFFSET) as *mut u32;
            // Safety: We assume that the register_addr is valid and already mapped into kernel space.
            let id = u16::try_from(unsafe { core::ptr::read(id_ptr) })
                .expect("device ID should be between 0 and 65535, 0 if not set");
            log::info!("shmem ID is: {:?}", id);

            // Map shmem into kernel space
            kvspace
                .map_identity_with_offset(
                    PAddr::from(KERNEL_BASE),
                    PAddr::from(mem_region.address),
                    mem_region.size as usize,
                    MapAction::kernel() | MapAction::write(),
                )
                .expect("Failed to write potential shmem memory region addresses");

            // Map the MSI-X table into kernel space
            kvspace
                .map_identity_with_offset(
                    PAddr::from(KERNEL_BASE),
                    PAddr::from(msi_region.address),
                    msi_region.size as usize,
                    MapAction::kernel() | MapAction::write(),
                )
                .expect("Failed to map MSI-X table");

            Some(ShmemDevice {
                mem_addr: mem_region.address,
                mem_size: mem_region.size,
                id,
                doorbell: Arc::new(Mutex::new(
                    register_region.address + KERNEL_BASE + SHMEM_DOORBELL_OFFSET,
                )),
                device: Arc::new(Mutex::new(ivshmem_device)),
            })
        } else {
            log::error!("Unable to find IVSHMEM device");
            None
        }
    }

    pub(crate) fn set_doorbell(&self, vector: u16, id: u16) {
        // bit 0..15: vector, bit 16..31: peer ID
        let doorbell_value: u32 = ((id as u32) << 16) | (vector as u32);

        // Safety: We assume that the doorbell addr is correct & mapped into kernel space.;
        let doorbell = *self.doorbell.lock();
        let doorbell_ptr = doorbell as *mut u32;
        unsafe { core::ptr::write(doorbell_ptr, doorbell_value) };
        log::info!(
            "doorbell set to: {:#032b} (id={:#016b}, vector={:#016b})",
            doorbell_value,
            id,
            vector
        );
    }

    pub(crate) fn enable_msix_vector(
        &self,
        table_vector: usize,
        destination_id: u8,
        int_vector: u8,
    ) {
        assert!(int_vector >= 0x10);
        // TODO(correctness): not sure if upper range is exclusive or not, erring on side of caution?
        assert!(int_vector < 0xFE);
        // TODO(correctness): how to validate destination?

        let mut device = self.device.lock();
        let tbl_paddr = device
            .get_msix_irq_table_mut(&paddr_to_kernel_vaddr)
            .expect("Failed to get MSI-x Table from ivshmem PciDevice");
        log::debug!("MSI-X table {:?}", tbl_paddr);
        assert!(table_vector < tbl_paddr.len());

        log::info!(
            "Original MSI entry {:?} is {:?}",
            table_vector,
            tbl_paddr[table_vector]
        );

        // Use this to construct the message address register (lower 32-bits)
        let mut address_register: u64 = 0;

        // 31 - 20 -> fixed value for interrupts, 0xFEE
        address_register |= 0xFEE << 20;

        // 19 - 12 -> destination ID (target processor, bits 63:56 I/O Apic Redirection Table Entry)
        address_register |= (destination_id as u64) << 12;

        //  3      -> Redirection Hint (RH) 0 = destination field, 1 = depends on phys or log destination mode
        // Set RH=0 so that we use the destination id

        //  2      -> Destination Mode (DM) RH = 1, DM = 0 => physical, RH = 1, DM = 1 => logical, RH = 0, DM is ignored
        use x86::apic::DestinationMode;
        address_register |= (DestinationMode::Physical as u64) << 2;

        //  1 -  0 -> XX
        // I believe this stands for the destination??
        use x86::apic::DestinationShorthand;
        address_register |= DestinationShorthand::NoShorthand as u64;

        // Mask for reserved bits 11-4 is: 0111_1111_0000b = 0x07F0
        let reserved_mask = 0x00_00_07_F0;
        let set_addr_high = 0xFF_FF_FF_FF << 32;
        tbl_paddr[table_vector as usize].addr =
            (tbl_paddr[table_vector].addr & reserved_mask) | address_register | set_addr_high;

        // Use this to construct the new message address register
        let mut data_register: u32 = 0;

        // 15      -> Trigger Mode (0 - Edge, 1 - Level)
        use x86::apic::TriggerMode;
        data_register |= (TriggerMode::Edge as u32) << 15;

        // 14      -> Level for Trigger Mode (If TM=0, then _, if TM=0, 0 => deassert, 1 => assert)
        use x86::apic::Level;
        data_register |= (Level::Assert as u32) << 14;

        // 10 -  8 -> Delivery Mode (000: Fixed, 001: Lowest Priority, 010: SMI, 011: reserved, 100: NMI, 101: INIT, 110: reserved, 111: ExINT)
        use x86::apic::DeliveryMode;
        data_register |= (DeliveryMode::Fixed as u32) << 8;

        //  7 -  0 -> Vector (Range: 0x010 - 0xFEH)
        data_register |= int_vector as u32;

        // Reserved bits are: 63 - 32, 31 - 16, 13 - 11
        // So the low bits of the mask will look like this: 0011_1000_0000_0000b
        let reserved_mask = 0xFF_FF_38_00;
        tbl_paddr[table_vector].data =
            (tbl_paddr[table_vector].data & reserved_mask) | data_register;

        // Toggle the interrupt mask for this vector
        tbl_paddr[table_vector].vector_control ^= 0x1;

        log::info!(
            "New MSI entry {:?} is {:?}",
            table_vector,
            tbl_paddr[table_vector]
        );
    }
}

// The default size of the Shared memory queue is 32.
// The total size of two queues(sender and reciever) should be less
// that the MAX_SHMEM_TRANSPORT_SIZE.
const SHMEM_QUEUE_SIZE: usize = 32;
const_assert!(2 * SHMEM_QUEUE_SIZE * MAX_BUFF_LEN <= MAX_SHMEM_TRANSPORT_SIZE as usize);

#[cfg(feature = "rpc")]
pub(crate) fn create_shmem_transport(client_id: u64) -> KResult<ShmemTransport<'static>> {
    use crate::arch::rackscale::client::get_num_clients;
    use crate::cmdline::Mode;
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::Queue;
    use rpc::transport::shmem::{Receiver, Sender};

    assert!(client_id * MAX_SHMEM_TRANSPORT_SIZE <= SHMEM_DEVICE.mem_size);
    let transport_size = core::cmp::min(
        SHMEM_DEVICE.mem_size / get_num_clients(),
        MAX_SHMEM_TRANSPORT_SIZE,
    );
    let base_addr = SHMEM_DEVICE.mem_addr + KERNEL_BASE + client_id * transport_size;
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
    let mut size = SHMEM_DEVICE.mem_size;
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
