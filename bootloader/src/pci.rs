// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

use bit_field::BitField;
use core::fmt;
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

// https://wiki.osdev.org/PCI#Class_Codes
#[derive(Debug)]
enum ClassCode {
    IDE_Controller = 0x0101,
    SATA_Controller = 0x0106,
    Ethernet_Controller = 0x0200,
    VGA_Compatible_Controller = 0x0300,
    RAM_Controller = 0x0500,
    Host_Bridge = 0x0600,
    ISA_Bridge = 0x0601,
    Other_Bridge = 0x0680,
    Unknown = 0xffff,
}

impl From<u16> for ClassCode {
    fn from(value: u16) -> ClassCode {
        match value {
            0x0101 => ClassCode::IDE_Controller,
            0x0106 => ClassCode::SATA_Controller,
            0x0200 => ClassCode::Ethernet_Controller,
            0x0300 => ClassCode::VGA_Compatible_Controller,
            0x0500 => ClassCode::RAM_Controller,
            0x0600 => ClassCode::Host_Bridge,
            0x0601 => ClassCode::ISA_Bridge,
            0x0680 => ClassCode::Other_Bridge,
            _ => ClassCode::Unknown,
        }
    }
}

#[derive(Debug)]
enum BarType {
    IO,
    MEM,
}

impl From<bool> for BarType {
    fn from(value: bool) -> BarType {
        match value {
            true => BarType::IO,
            false => BarType::MEM,
        }
    }
}

#[derive(Debug)]
struct Bar {
    region_type: BarType,
    prefetchable: bool,
    address: u64,
    size: u64,
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

                let size = unsafe {
                    self.0 .0.write(offset, 0xffffffff);
                    let mut size = self.0 .0.read(offset);
                    self.0 .0.write(offset, address);

                    if size == 0x0 {
                        return None;
                    }

                    // https://wiki.osdev.org/PCI#Base_Address_Registers says:
                    // - Clear lower 4 bits
                    // - Invert all 32-bits
                    // - Add 1 to the result
                    // TODO: No mention about how to handle > 32-bit sizes
                    size.set_bits(0..4, 0);
                    size = !size;
                    size += 1;

                    size
                };

                let (address, size) = {
                    match locatable {
                        // 32-bit address
                        0 => (address as u64, size as u64),
                        // 20-bit address
                        1 => unreachable!("Unable to handle 20-bit BAR address"),
                        // 64-bit address
                        2 => {
                            // For 64-bit Memory Space BARs:
                            // ((BAR[x] & 0xFFFFFFF0) + ((BAR[x + 1] & 0xFFFFFFFF) << 32))
                            let next_offset = offset + 4;
                            let mut address = (address & 0xFFFFFFF0) as u64;
                            let next_bar = self.0 .0.read(next_offset) & 0xFFFFFFFF;
                            address += (next_bar as u64) << 32;

                            // Size for 64-bit Memory Space BARs:
                            self.0 .0.write(next_offset, 0xffffffff);
                            let mut next_size = self.0 .0.read(next_offset);
                            self.0 .0.write(next_offset, next_bar);
                            next_size = !next_size;
                            next_size += 1;

                            (address, ((next_size as u64) << 32 | size as u64))
                        }
                        _ => panic!("Unknown locatable"),
                    }
                };

                trace!("{:?} {} {:#x} {}", bartype, prefetchable, address, size);
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
        let (_revision, base_class, sub_class, interface) = self.revision_and_class();
        let class = (base_class as u16) << 8 | (sub_class as u16);
        class.into()
    }
}

pub fn pci_init() {
    // PCI supports up to 256 buses
    for bus in 0..=255 {
        // PCI supports up to 32 devices per bus
        for device in 0..=31 {
            // PCI supports up to 8 functions per device
            for fun in 0..=7 {
                let pci_device = PCIDevice::new(bus, device, fun);
                if pci_device.is_present() {
                    info!(
                        "{:?} - {:?} - {:?} \t {:#x} - {:#x}",
                        pci_device.0 .0,
                        pci_device.device_type(),
                        pci_device.device_class(),
                        pci_device.vendor_id(),
                        pci_device.device_id(),
                    );

                    if pci_device.vendor_id() == 0x1af4 {
                        info!("{:?}", pci_device.bar(0));
                        info!("{:?}", pci_device.bar(2));
                    }
                }
            }
        }
    }
}
