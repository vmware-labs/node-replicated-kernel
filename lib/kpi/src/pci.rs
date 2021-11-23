// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

use bit_field::BitField;
use core::fmt;
use log::trace;
use x86::io;

static PCI_CONF_ADDR: u16 = 0xCF8;
static PCI_CONF_DATA: u16 = 0xCFC;

pub type VendorId = u16;
pub type DeviceId = u16;
pub type DeviceRevision = u8;
pub type BaseClass = u8;
pub type SubClass = u8;
pub type Interface = u8;
pub type HeaderType = u8;

#[derive(Debug)]
pub enum PCIDeviceType {
    ENDPOINT = 0x00,
    PciBRIDGE = 0x01,
}

pub struct PCIAddress(u32);

impl PCIAddress {
    fn new(bus: u8, device: u8, function: u8) -> PCIAddress {
        assert!(device <= 31);
        assert!(function <= 7);

        trace!("address ({:2}:{:2}.{:1})", bus, device, function);
        PCIAddress(
            (1 << 31) | ((bus as u32) << 16) | ((device as u32) << 11) | ((function as u32) << 8),
        )
    }

    fn read(&self, offset: u32) -> u32 {
        let addr = self.0 | offset;

        unsafe {
            io::outl(PCI_CONF_ADDR, addr);
            io::inl(PCI_CONF_DATA)
        }
    }

    fn write(&self, offset: u32, value: u32) {
        let addr = self.0 | offset;

        unsafe {
            io::outl(PCI_CONF_ADDR, addr);
            io::outl(PCI_CONF_DATA, value);
        }
    }
}

impl fmt::Debug for PCIAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}.{}",
            self.0.get_bits(16..24) as u8,
            self.0.get_bits(11..16) as u8,
            self.0.get_bits(8..11) as u8
        )
    }
}

pub struct PCIHeader(PCIAddress);

impl PCIHeader {
    pub fn new(bus: u8, device: u8, function: u8) -> PCIHeader {
        let addr = PCIAddress::new(bus, device, function);
        PCIHeader(addr)
    }

    pub fn is_valid(&self) -> bool {
        self.0.read(0) != 0xFFFFFFFF
    }
}

// https://wiki.osdev.org/PCI#Class_Codes
#[derive(Debug)]
pub enum ClassCode {
    IDEController = 0x0101,
    SATAController = 0x0106,
    EthernetController = 0x0200,
    VGACompatibleController = 0x0300,
    RAMController = 0x0500,
    HostBridge = 0x0600,
    ISABridge = 0x0601,
    OtherBridge = 0x0680,
    Unknown = 0xffff,
}

impl From<u16> for ClassCode {
    fn from(value: u16) -> ClassCode {
        match value {
            0x0101 => ClassCode::IDEController,
            0x0106 => ClassCode::SATAController,
            0x0200 => ClassCode::EthernetController,
            0x0300 => ClassCode::VGACompatibleController,
            0x0500 => ClassCode::RAMController,
            0x0600 => ClassCode::HostBridge,
            0x0601 => ClassCode::ISABridge,
            0x0680 => ClassCode::OtherBridge,
            _ => ClassCode::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BarType {
    IO,
    Mem,
}

impl From<bool> for BarType {
    fn from(value: bool) -> BarType {
        match value {
            true => BarType::IO,
            false => BarType::Mem,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Bar {
    region_type: BarType,
    prefetchable: bool,
    address: u64,
    size: u64,
}

pub struct PCIDevice(PCIHeader);

impl PCIDevice {
    pub fn new(bus: u8, device: u8, function: u8) -> PCIDevice {
        let header = PCIHeader::new(bus, device, function);
        PCIDevice(header)
    }

    pub fn is_present(&self) -> bool {
        self.0.is_valid()
    }

    pub fn device_type(&self) -> PCIDeviceType {
        let header = self.0 .0.read(0x0c);
        match header.get_bits(16..23) as u8 {
            0x00 => PCIDeviceType::ENDPOINT,
            0x01 => PCIDeviceType::PciBRIDGE,
            _ => panic!("Unknown device type"),
        }
    }

    pub fn vendor_id(&self) -> VendorId {
        self.0 .0.read(0x00) as VendorId
    }

    pub fn device_id(&self) -> DeviceId {
        self.0 .0.read(0x02) as DeviceId
    }

    pub fn bar(&self, index: u8) -> Option<Bar> {
        match self.device_type() {
            PCIDeviceType::ENDPOINT => assert!(index < 6),
            PCIDeviceType::PciBRIDGE => assert!(index < 2),
        }

        let offset = 0x10 + (index as u32) * 4;
        let base = self.0 .0.read(offset);
        let bartype = base.get_bit(0);

        match bartype {
            true => unreachable!("Unable to handle IO BARs"),
            false => {
                let locatable = base.get_bits(1..3);
                let prefetchable = base.get_bit(3);
                let address = base.get_bits(4..32) << 4;

                self.0 .0.write(offset, 0xFFFFFFFF);
                let size_encoded = self.0 .0.read(offset);
                self.0 .0.write(offset, address);

                if size_encoded == 0x0 {
                    return None;
                }

                // To get the region size using BARs:
                // - Clear lower 4 bits
                // - Invert all all-bits
                // - Add 1 to the result
                // Ref: https://wiki.osdev.org/PCI#Base_Address_Registers
                let (address, size) = {
                    match locatable {
                        // 32-bit address
                        0 => {
                            let size = !(size_encoded & !0xF) + 1;
                            (address as u64, size as u64)
                        }
                        // 64-bit address
                        2 => {
                            let next_offset = offset + 4;
                            let next_bar = self.0 .0.read(next_offset);
                            let address = (next_bar as u64 & 0xFFFFFFFF) << 32
                                | (address & 0xFFFFFFF0) as u64;

                            // Size for 64-bit Memory Space BARs:
                            self.0 .0.write(next_offset, 0xFFFFFFFF);
                            let msb_size_encoded = self.0 .0.read(next_offset);
                            self.0 .0.write(next_offset, next_bar);
                            let size = (msb_size_encoded as u64) << 32 | size_encoded as u64;

                            (address, (!(size & !0xF) + 1))
                        }
                        _ => panic!("Unknown locatable"),
                    }
                };

                Some(Bar {
                    region_type: bartype.into(),
                    prefetchable,
                    address,
                    size,
                })
            }
        }
    }

    pub fn revision_and_class(&self) -> (DeviceRevision, BaseClass, SubClass, Interface) {
        let field = { self.0 .0.read(0x08) };
        (
            field.get_bits(0..8) as DeviceRevision,
            field.get_bits(24..32) as BaseClass,
            field.get_bits(16..24) as SubClass,
            field.get_bits(8..16) as Interface,
        )
    }

    pub fn device_class(&self) -> ClassCode {
        let (_revision, base_class, sub_class, _interface) = self.revision_and_class();
        let class = (base_class as u16) << 8 | (sub_class as u16);
        class.into()
    }
}

pub fn pci_device_lookup(bus: u8, device: u8, function: u8) -> Option<PCIDevice> {
    let device = PCIDevice::new(bus, device, function);
    if device.is_present() {
        Some(device)
    } else {
        None
    }
}

pub fn pci_device_lookup_with_devinfo(
    vendor_id: VendorId,
    device_id: DeviceId,
) -> Option<PCIDevice> {
    let mut pci_device = None;
    for bus in 0..=255 {
        for device in 0..=31 {
            for function in 0..=7 {
                let dev = pci_device_lookup(bus, device, function);
                if let Some(dev) = dev {
                    if dev.vendor_id() == vendor_id && dev.device_id() == device_id {
                        pci_device = Some(dev);
                        break;
                    }
                }
            }
        }
    }
    pci_device
}
