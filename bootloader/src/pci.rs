// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

use bit_field::BitField;
use core::fmt;
use pci_types::device_type::DeviceType;
use x86::io;

static PCI_CONF_ADDR: u16 = 0xcf8;
static PCI_CONF_DATA: u16 = 0xcfc;

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

struct PCIAddress(u32);

impl PCIAddress {
    fn new(bus: u8, device: u8, function: u8) -> PCIAddress {
        assert!(bus <= 255);
        assert!(device <= 31);
        assert!(function <= 7);

        PCIAddress(
            (1 << 31) | ((bus as u32) << 16) | ((device as u32) << 11) | ((function as u32) << 8),
        )
    }

    fn read(&self, offset: u32) -> u32 {
        let addr = self.0 | offset;

        let v = unsafe {
            io::outl(PCI_CONF_ADDR, addr);
            io::inl(PCI_CONF_DATA)
        };
        v
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
        let header = PCIHeader(addr);
        header
    }

    pub fn is_valid(&self) -> bool {
        if self.0.read(0) != 0xffffffff {
            true
        } else {
            false
        }
    }
}

struct PCIDevice(PCIHeader);

impl PCIDevice {
    pub fn new(bus: u8, device: u8, function: u8) -> PCIDevice {
        let header = PCIHeader::new(bus, device, function);
        let device = PCIDevice(header);
        device
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

    pub fn revision_and_class(&self) -> (DeviceRevision, BaseClass, SubClass, Interface) {
        let field = { self.0 .0.read(0x08) };
        (
            field.get_bits(0..8) as DeviceRevision,
            field.get_bits(24..32) as BaseClass,
            field.get_bits(16..24) as SubClass,
            field.get_bits(8..16) as Interface,
        )
    }

    pub fn device_category(&self) -> DeviceType {
        let (revision, base_class, sub_class, interface) = self.revision_and_class();
        DeviceType::from((base_class, sub_class))
    }
}

pub fn pci_init() {
    let start_offset = 0x0;

    // PCI supports up to 256 buses
    for bus in 0..=255 {
        // PCI supports up to 32 devices per bus
        for device in 0..=31 {
            // PCI supports up to 8 functions per device
            for fun in 0..=7 {
                let pci_device = PCIDevice::new(bus, device, fun);
                if pci_device.is_present() {
                    info!(
                        "{:?} - {:?} - {:?}",
                        pci_device.0 .0,
                        pci_device.device_type(),
                        pci_device.device_category()
                    );
                }
            }
        }
    }
}
