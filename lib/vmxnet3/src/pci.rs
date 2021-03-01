use log::error;

use x86::bits64::paging::{PAddr, VAddr};
use x86::io;

pub const KERNEL_BASE: u64 = 0x400000000000;

pub trait DmaObject {
    fn paddr(&self) -> PAddr {
        PAddr::from(&*self as *const Self as *const () as u64) - PAddr::from(KERNEL_BASE)
    }

    fn vaddr(&self) -> VAddr {
        VAddr::from(&*self as *const Self as *const () as usize)
    }
}

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
    error!(
        "confread ({:#x} {:#x} {:#x}) reg({}) val = {:#x}",
        bus, dev, fun, reg, v
    );

    v
}

#[allow(unused)]
pub(crate) unsafe fn confwrite(bus: u32, dev: u32, fun: u32, reg: u32, value: u32) {
    error!(
        "confwrite ({:#x} {:#x} {:#x}) reg({:#x}) = value({:#x})",
        bus, dev, fun, reg, value
    );

    let addr = pci_bus_address(bus, dev, fun, reg);
    io::outl(PCI_CONF_ADDR, addr);
    io::outl(PCI_CONF_DATA, value);
}

pub(crate) unsafe fn busread(bar_base: u64, offset: u64) -> u32 {
    let v = *((bar_base + offset) as *mut u32);
    error!("busread ({:#x} + {:#x}) val = {:#x}", bar_base, offset, v);
    v
}

pub(crate) unsafe fn buswrite(bar_base: u64, offset: u64, value: u32) {
    error!(
        "buswrite ({:#x} + {:#x}) = value({:#x})",
        bar_base, offset, value
    );
    *((bar_base + offset) as *mut u32) = value;
}
