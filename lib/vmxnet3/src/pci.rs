// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

#![allow(unused)]
use log::{debug, error, trace};
use x86::io;

pub use driverkit::iomem::DmaObject;

pub use kpi::KERNEL_BASE;
use x86::bits64::paging::{PAddr, VAddr};

static PCI_CONF_ADDR: u16 = 0xcf8;
static PCI_CONF_DATA: u16 = 0xcfc;

#[inline]
fn pci_bus_address(bus: u32, dev: u32, fun: u32, reg: u32) -> u32 {
    assert!(reg <= 0xfc);

    (1 << 31) | (bus << 16) | (dev << 11) | (fun << 8) | (reg as u32 & 0xfc)
}

pub(crate) unsafe fn confread(bus: u32, dev: u32, fun: u32, reg: u32) -> u32 {
    let addr = pci_bus_address(bus, dev, fun, reg);

    io::outl(PCI_CONF_ADDR, addr);
    let v = io::inl(PCI_CONF_DATA);
    trace!(
        "confread ({:#x} {:#x} {:#x}) reg({}) val = {:#x}",
        bus,
        dev,
        fun,
        reg,
        v
    );

    v
}

pub(crate) unsafe fn confwrite(bus: u32, dev: u32, fun: u32, reg: u32, value: u32) {
    trace!(
        "confwrite ({:#x} {:#x} {:#x}) reg({:#x}) = value({:#x})",
        bus,
        dev,
        fun,
        reg,
        value
    );

    let addr = pci_bus_address(bus, dev, fun, reg);
    io::outl(PCI_CONF_ADDR, addr);
    io::outl(PCI_CONF_DATA, value);
}

pub(crate) unsafe fn busread(bar_base: u64, offset: u64) -> u32 {
    let v = *((bar_base + offset) as *mut u32);
    trace!("busread ({:#x} + {:#x}) val = {:#x}", bar_base, offset, v);
    v
}

pub(crate) unsafe fn buswrite(bar_base: u64, offset: u64, value: u32) {
    trace!(
        "buswrite ({:#x} + {:#x}) = value({:#x})",
        bar_base,
        offset,
        value
    );
    *((bar_base + offset) as *mut u32) = value;
}

pub(crate) trait BarIO {
    fn read_bar0(&self, offset: u64) -> u32;
    fn write_bar0(&self, offset: u64, data: u32);
    fn read_bar1(&self, offset: u64) -> u32;
    fn write_bar1(&self, offset: u64, data: u32);
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct BarAccess {
    /// Bus, device, function triplet of PCI device
    pub pci_addr: (u32, u32, u32),
    /// IO memory address of BAR0
    pub bar0: u64,
    /// IO memory address of BAR1
    pub bar1: u64,
}

#[cfg(not(test))]
impl BarAccess {
    pub fn new(bus: u32, dev: u32, fun: u32) -> Self {
        unsafe {
            let devline = confread(bus, dev, fun, 0x0);
            assert_eq!(devline, 0x7b015ad, "Sanity check for vmxnet3");

            let bar0 = confread(bus, dev, fun, 0x10);
            let bar1 = confread(bus, dev, fun, 0x14);
            //let bar_msix = pci::confread(BUS, DEV, FUN, 0x7);

            debug!("BAR0 at: {:#x}", bar0);
            debug!("BAR1 at: {:#x}", bar1);
            //debug!("MSI-X at: {:#x}", bar_msi);

            BarAccess {
                pci_addr: (bus, dev, fun),
                bar0: bar0 as u64 + KERNEL_BASE,
                bar1: bar1 as u64 + KERNEL_BASE,
            }
        }
    }
}

#[cfg(not(test))]
impl BarIO for BarAccess {
    fn read_bar0(&self, offset: u64) -> u32 {
        unsafe { busread(self.bar0, offset) }
    }

    fn write_bar0(&self, offset: u64, data: u32) {
        unsafe { buswrite(self.bar0, offset, data) };
    }

    fn read_bar1(&self, offset: u64) -> u32 {
        unsafe { busread(self.bar1, offset) }
    }

    fn write_bar1(&self, offset: u64, data: u32) {
        unsafe { buswrite(self.bar1, offset, data) };
    }
}

#[cfg(test)]
impl BarAccess {
    pub fn new(bus: u32, dev: u32, fun: u32) -> Self {
        BarAccess {
            pci_addr: (bus, dev, fun),
            bar0: 0x0,
            bar1: 0x0,
        }
    }
}

#[cfg(test)]
impl BarIO for BarAccess {
    fn read_bar0(&self, _offset: u64) -> u32 {
        0xdead
    }

    fn write_bar0(&self, _offset: u64, _data: u32) {}

    fn read_bar1(&self, _offset: u64) -> u32 {
        0xbeef
    }

    fn write_bar1(&self, _offset: u64, _data: u32) {}
}
