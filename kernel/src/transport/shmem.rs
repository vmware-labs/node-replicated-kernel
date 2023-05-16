// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use alloc::sync::Arc;

use abomonation::{unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use driverkit::pci::{CapabilityId, CapabilityType, PciDevice};
use lazy_static::lazy_static;
use spin::Mutex;

use kpi::KERNEL_BASE;

use crate::memory::vspace::MapAction;
use crate::memory::{paddr_to_kernel_vaddr, PAddr, BASE_PAGE_SIZE};
use crate::pci::claim_device;

#[cfg(feature = "rpc")]
use {
    crate::cmdline::Transport,
    crate::error::{KError, KResult},
    crate::memory::{mcache::MCache, Frame, SHARED_AFFINITY},
    alloc::boxed::Box,
    kpi::system::MachineId,
    rpc::rpc::MAX_BUFF_LEN,
    rpc::transport::ShmemTransport,
    static_assertions::const_assert,
};

// Register information from:
// https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt
// other fields are reserved for revision 1
const SHMEM_IVPOSITION_OFFSET: u64 = 8;
const SHMEM_DOORBELL_OFFSET: u64 = 12;

#[derive(Debug, Default)]
pub(crate) struct ShmemRegion {
    pub(crate) base: u64,
    pub(crate) size: u64,
}
unsafe_abomonate!(ShmemRegion: base, size);

#[cfg(feature = "rackscale")]
impl ShmemRegion {
    pub(crate) fn get_frame(&self, frame_offset: u64) -> Frame {
        Frame::new(
            PAddr(self.base + frame_offset),
            self.size as usize,
            SHARED_AFFINITY,
        )
    }

    pub(crate) fn get_shmem_manager<const BP: usize, const LP: usize>(
        &self,
        frame_offset: u64,
    ) -> Option<Box<MCache<BP, LP>>> {
        if self.size > 0 {
            let frame = self.get_frame(frame_offset);
            Some(Box::new(MCache::<BP, LP>::new_with_frame(
                SHARED_AFFINITY,
                frame,
            )))
        } else {
            None
        }
    }
}

lazy_static! {
    pub(crate) static ref SHMEM_DEVICE: ShmemDevice =
        ShmemDevice::new().expect("Failed to get SHMEM device");
}

pub(crate) struct ShmemDevice {
    // Shmem memory region.
    pub(crate) region: ShmemRegion,

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
            let register_region = ivshmem_device.bar(0).expect("Unable to find shmem BAR0");
            log::info!(
                "Found IVSHMEM device register region with base paddr {:X} and size {}",
                register_region.address,
                register_region.size
            );

            let mem_region = ivshmem_device.bar(2).expect("Unable to find shmem BAR2");
            log::info!(
                "Found IVSHMEM device memory region with base paddr {:X} and size {}, range=[{:X}-{:X}]",
                mem_region.address,
                mem_region.size,
                mem_region.address,
                mem_region.address + mem_region.size
            );

            let msi_region = if let Some(cap) = ivshmem_device
                .capabilities()
                .find(|cap| cap.id == CapabilityId::MsiX)
            {
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
                    // TODO(rackscale, correctness): this is a hack because the region is < BASE_PAGE_REGION but map assumes at least BASE_PAGE_SIZE
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
                region: ShmemRegion {
                    base: mem_region.address,
                    size: mem_region.size,
                },
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

#[cfg(feature = "rpc")]
const SHMEM_QUEUE_SIZE: usize = 32;

// The total size of two queues(sender and reciever) should be less than the transport size.
#[cfg(feature = "rpc")]
const_assert!(2 * SHMEM_QUEUE_SIZE * MAX_BUFF_LEN <= SHMEM_TRANSPORT_SIZE as usize);

#[cfg(feature = "rpc")]
pub(crate) const SHMEM_TRANSPORT_SIZE: u64 = 2 * 1024 * 1024;

#[cfg(feature = "rpc")]
pub(crate) fn create_shmem_transport(machine_id: MachineId) -> KResult<ShmemTransport<'static>> {
    use crate::cmdline::Mode;
    use rpc::transport::shmem::allocator::ShmemAllocator;
    use rpc::transport::shmem::Queue;
    use rpc::transport::shmem::{Receiver, Sender};
    let machine_id = machine_id as u64;
    assert!(SHMEM_DEVICE.region.size >= (machine_id + 1) * SHMEM_TRANSPORT_SIZE);

    let base_addr = SHMEM_DEVICE.region.base + KERNEL_BASE + machine_id * SHMEM_TRANSPORT_SIZE;
    let allocator = ShmemAllocator::new(base_addr, SHMEM_TRANSPORT_SIZE);
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
                machine_id,
                SHMEM_TRANSPORT_SIZE,
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
                SHMEM_TRANSPORT_SIZE,
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
    use crate::arch::rackscale::registration::initialize_client;
    use rpc::client::Client;

    // Set up the transport
    let transport = Box::try_new(create_shmem_transport(*crate::environment::MACHINE_ID)?)?;

    // Create the client
    let client = Box::try_new(Client::new(transport))?;
    initialize_client(client, send_client_data)
}

#[cfg(feature = "rackscale")]
pub(crate) fn get_affinity_shmem() -> ShmemRegion {
    get_affinity_shmem_by_mid(*crate::environment::MACHINE_ID)
}

#[cfg(feature = "rackscale")]
pub(crate) fn get_affinity_shmem_by_mid(mid: MachineId) -> ShmemRegion {
    let mut base = SHMEM_DEVICE.region.base;
    let mut size = SHMEM_DEVICE.region.size;

    if crate::CMDLINE
        .get()
        .map_or(false, |c| c.transport == Transport::Shmem)
    {
        let num_workers = (*crate::environment::NUM_MACHINES - 1) as u64;
        // Offset base to ignore shmem used for client transports
        base += SHMEM_TRANSPORT_SIZE * num_workers;

        // Remove amount used for transport from the size
        size = core::cmp::max(0, size - SHMEM_TRANSPORT_SIZE * num_workers);
    };

    // Align on base page boundaries
    let pages_per_worker =
        (size / BASE_PAGE_SIZE as u64) / (*crate::environment::NUM_MACHINES as u64);
    let size_per_worker = pages_per_worker * BASE_PAGE_SIZE as u64;

    base += size_per_worker * (mid as u64) as u64;
    log::trace!(
        "Shmem affinity region: base={:x}, size={:x}, range: [{:X}-{:X}]",
        base,
        size_per_worker,
        base,
        base + size_per_worker - 1,
    );

    ShmemRegion {
        base,
        size: size_per_worker,
    }
}

#[cfg(feature = "rackscale")]
#[inline(always)]
pub(crate) fn is_shmem_frame(frame: Frame, is_affinity: bool, is_kaddr: bool) -> bool {
    is_shmem_addr(frame.base.as_u64(), is_affinity, is_kaddr)
        && is_shmem_addr(
            frame.base.as_u64() + (frame.size as u64) - 1,
            is_affinity,
            is_kaddr,
        )
}

#[cfg(feature = "rackscale")]
#[inline(always)]
pub(crate) fn is_shmem_addr(addr: u64, is_affinity: bool, is_kaddr: bool) -> bool {
    let offset = if is_kaddr { KERNEL_BASE } else { 0 };

    let (shmem_start, shmem_size) = if is_affinity {
        let frame = get_affinity_shmem().get_frame(offset);
        (frame.base.as_u64(), frame.size as u64)
    } else {
        let mut shmem_offset = 0;
        if crate::CMDLINE
            .get()
            .map_or(false, |c| c.transport == Transport::Shmem)
        {
            let num_workers = (*crate::environment::NUM_MACHINES - 1) as u64;
            shmem_offset = SHMEM_TRANSPORT_SIZE * num_workers;
        }
        (
            SHMEM_DEVICE.region.base + offset + shmem_offset,
            SHMEM_DEVICE.region.size - shmem_offset,
        )
    };
    addr >= shmem_start && addr <= shmem_start + shmem_size
}
